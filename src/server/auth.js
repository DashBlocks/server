import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import app, { resend } from "../app.js";
import * as vars from "./vars.js";
import {
	isValidUsername,
	isValidEmail,
	generateVerificationCode,
	generateUserObject,
	getUserIndexData,
	securityCheck,
	verifyAuth,
	authLimiter,
	registerLimiter,
	sendEventMessage
} from "./helpers.js";
import * as storage from "./storage.js";

const verificationCodes = new Map();
const VERIFICATION_CODE_EXPIRY_MS = 10 * 60 * 1000;

const storeVerificationCode = (email, code, metadata = {}) => {
	const normalizedEmail = email.toLowerCase();
	verificationCodes.set(normalizedEmail, {
		code,
		expiresAt: Date.now() + VERIFICATION_CODE_EXPIRY_MS,
		...metadata
	});
};

const getStoredVerificationCode = (email) => {
	const normalizedEmail = email.toLowerCase();
	const record = verificationCodes.get(normalizedEmail);
	if (!record) return null;
	if (Date.now() > record.expiresAt) {
		verificationCodes.delete(normalizedEmail);
		return null;
	}
	return record;
};

const clearStoredVerificationCode = (email) => {
	verificationCodes.delete(email.toLowerCase());
};

const sendVerificationEmail = async (email, code) => {
	const { data, error } = await resend.emails.send({
		from: "DashBlocks Verification <verify@noreply.dashblocks.org>",
		to: [email],
		subject: "Your DashBlocks verification code",
		html: `<p>Your verification code is <strong>${code}</strong></p><p>It expires in 10 minutes</p>`
	});
	if (error) throw new Error(error.message || "Failed to send verification email");
	return data;
};

const setAuthCookie = (res, token) => {
	res.cookie("auth_token", token, {
		httpOnly: true,
		secure: true,
		sameSite: "none",
		maxAge: 7 * 24 * 60 * 60 * 1000,
		path: "/"
	});
};

app.post("/auth/send-verification", authLimiter, async (req, res) => {
	try {
		const email = req.body?.email?.trim();
		if (!email || !isValidEmail(email))
			return res.status(400).json({ ok: false, error: "Invalid email address" });

		const code = generateVerificationCode();
		storeVerificationCode(email, code, { purpose: req.body?.purpose || "register" });
		await sendVerificationEmail(email, code);
		res.json({ ok: true, message: "Verification code sent to your email" });
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});

app.post("/auth/register", authLimiter, registerLimiter, securityCheck, async (req, res) => {
	try {
		const { username, password, email, verificationCode } = req.body;

		if (!isValidUsername(username))
			return res.status(400).json({
				ok: false,
				error:
					"Username must be 3-20 characters long and contain only letters, numbers, underscores, and dashes"
			});
		if (vars.FORBIDDEN_USERNAMES.includes(username.toLowerCase()))
			return res
				.status(400)
				.json({ ok: false, error: "You cannot use this username" });
		if (!password || password.length < 8 || password.length > 100)
			return res
				.status(400)
				.json({ ok: false, error: "Password must be 8-100 characters long" });
		if (!email || !isValidEmail(email))
			return res.status(400).json({ ok: false, error: "Invalid email address" });

		const index = await storage.getIndex();
		if (index.users[username.toLowerCase()])
			return res.status(400).json({ ok: false, error: "Username taken" });
		if (!verificationCode)
			return res.status(400).json({ ok: false, error: "Verification code is required" });

		const storedCode = getStoredVerificationCode(email);
		if (!storedCode || storedCode.code !== verificationCode)
			return res.status(400).json({ ok: false, error: "Invalid or expired verification code" });

		if (Object.values(index.users).some((user) => user.email?.toLowerCase() === email.toLowerCase()))
			return res.status(400).json({ ok: false, error: "Email already in use" });

		const hashedPassword = await bcrypt.hash(password, 12);
		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
        
		const userId = index.nextUserId;

		const newUserMetadata = {
			id: userId,
			username,
			email,
			scratchUsername: null,
			role: "dasher",
			banned: false,
			ip: userIp,
			description: "",
			avatarId: 1,
			followers: [],
			following: [],
			projects: [],
			firedProjects: [],
			messages: [
				{
					type: "joined",
					date: new Date().toISOString()
				}
			],
			joinedAt: new Date().toISOString(),
			lastActive: new Date().toISOString(),
			actions: [],
			recommendedProject: {
				id: null,
				name: "Unknown",
				thumbnailId: 1
			},
			links: [],
			achievements: [],
			gradient: null,
			subscription: {
				status: "none",
				startDate: null,
				endDate: null
			}
		};

		const userData = { username, password: hashedPassword, ip: userIp, email };
		await storage.createUserJson(userId, userData);

		index.users[username.toLowerCase()] = newUserMetadata;
		index.nextUserId++;
		await storage.updateIndex(index);
		clearStoredVerificationCode(email);

		const token = jwt.sign({ userId, username }, vars.JWT_SECRET, {
			expiresIn: "7d"
		});
		setAuthCookie(res, token);

		res.json({ ok: true, userId, username });
		sendEventMessage(`New account: <b>${username}</b> (id ${userId})`);
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});

app.post("/auth/login", authLimiter, securityCheck, async (req, res) => {
	try {
		const { userId, password } = req.body;
		const index = await storage.getIndex();
		
		const user = getUserIndexData(index, userId);
		if (!user) throw new Error();

		const storedUser = await storage.readUserJson(user.id);

		if (await bcrypt.compare(password, storedUser.password)) {
			if (storedUser.email) {
				const code = generateVerificationCode();
				storeVerificationCode(storedUser.email, code, { purpose: "login", userId: user.id });
				await sendVerificationEmail(storedUser.email, code);
				return res.status(201).json({
					ok: true,
					requiresVerification: true,
					userId: user.id,
					username: user.username,
					message: "Verification code sent to your email"
				});
			}

			user.ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
			user.lastActive = new Date().toISOString();
			await storage.updateIndex(index);

			const token = jwt.sign({ userId: user.id, username: user.username }, vars.JWT_SECRET, { expiresIn: "7d" });
			setAuthCookie(res, token);
			res.json({ ok: true, userId: user.id, username: user.username });
		} else {
			throw new Error();
		}
	} catch (_) {
		res.status(401).json({ ok: false, error: "Invalid target or password" });
	}
});

app.post("/auth/verify-login", authLimiter, securityCheck, async (req, res) => {
	try {
		const { userId, verificationCode } = req.body;
		const index = await storage.getIndex();
		const user = getUserIndexData(index, userId);
		if (!user) return res.status(404).json({ ok: false, error: "User not found" });

		const storedUser = await storage.readUserJson(user.id);
		if (!storedUser.email) {
			return res.status(400).json({ ok: false, error: "No email address is associated with this account" });
		}

		const storedCode = getStoredVerificationCode(storedUser.email);
		if (!storedCode || storedCode.purpose !== "login" || storedCode.userId !== user.id || storedCode.code !== verificationCode) {
			return res.status(400).json({ ok: false, error: "Invalid or expired verification code" });
		}

		clearStoredVerificationCode(storedUser.email);
		user.ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
		user.lastActive = new Date().toISOString();
		await storage.updateIndex(index);

		const token = jwt.sign({ userId: user.id, username: user.username }, vars.JWT_SECRET, { expiresIn: "7d" });
		setAuthCookie(res, token);
		res.json({ ok: true, userId: user.id, username: user.username });
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});

app.get("/session", verifyAuth, securityCheck, async (req, res) => {
	const index = await storage.getIndex();
	const metadata = index.users[req.user.username.toLowerCase()];
	res.json({
		ok: true,
		user: {
			...generateUserObject(metadata),
			email: metadata?.email || null,
			firedProjects: metadata?.firedProjects || [],
			subscription: metadata?.subscription || { status: "none", startDate: null, endDate: null }
		}
	});
});

app.get("/session/messages", verifyAuth, securityCheck, async (req, res) => {
	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
	offset = isNaN(offset) ? 0 : Math.max(0, offset);

	const index = await storage.getIndex();
	const metadata = index.users[req.user.username.toLowerCase()];
	const messages = (metadata?.messages || []).slice(offset, offset + limit);
	res.json({ ok: true, messages });
});

app.get("/session/activity", verifyAuth, securityCheck, async (req, res) => {
	try {
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);

		const index = await storage.getIndex();
		const user = index.users[req.user.username.toLowerCase()];

		const activity = [];
		for (const followed of (user.following || [])) {
			const followedData = index.users[followed.username.toLowerCase()];
			if (followedData?.actions?.length > 0) {
				activity.push(...followedData.actions.map(action => ({
					...action,
					author: {
						id: followedData.id,
						username: followedData.username,
						profile: {
							avatarId: followedData.id
						}
					}
				})));
			}
		}

		activity.sort((a, b) => new Date(b.date) - new Date(a.date));
		res.json({ ok: true, activity: activity.slice(offset, offset + limit) });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to fetch activity" });
	}
});

app.get("/auth/logout", verifyAuth, securityCheck, (_, res) => {
	res.clearCookie("auth_token", {
		httpOnly: true,
		secure: true,
		sameSite: "none",
		path: "/"
	});
	return res.json({ ok: true, message: "Logged out" });
});

app.post("/auth/change-password", verifyAuth, securityCheck, authLimiter, async (req, res) => {
	try {
		const { currentPassword, newPassword } = req.body;
		if (!currentPassword || !newPassword)
			return res.status(400).json({ ok: false, error: "Current and new password required" });

		if (newPassword.length < 8 || newPassword.length > 100)
			return res.status(400).json({ ok: false, error: "Password must be 8-100 characters long" });
		const index = await storage.getIndex();
		const userIndexData = index.users[req.user.username.toLowerCase()];
		const storedUser = await storage.readUserJson(userIndexData.id);

		if (!(await bcrypt.compare(currentPassword, storedUser.password)))
			return res.status(401).json({ ok: false, error: "Current password is incorrect" });

		storedUser.password = await bcrypt.hash(newPassword, 12);
		await storage.updateUserJson(userIndexData.id, storedUser);

		res.clearCookie("auth_token", {
			httpOnly: true,
			secure: true,
			sameSite: "none",
			path: "/"
		});

		res.json({ ok: true, message: "Password changed. Log in now" });
		sendEventMessage(`Password changed: <b>${req.user.username}</b> (id ${req.user.userId})`);
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});

app.post("/auth/delete-account", verifyAuth, securityCheck, authLimiter, async (req, res) => {
	try {
		const { password } = req.body;
		const index = await storage.getIndex();
		const usernameLower = req.user.username.toLowerCase();
		const userIndexData = index.users[usernameLower];
        
		if (!userIndexData) return res.status(404).json({ ok: false, error: "User not found" });

		const storedUser = await storage.readUserJson(userIndexData.id);

		if (!(await bcrypt.compare(password, storedUser.password)))
			return res.status(401).json({ ok: false, error: "Password is incorrect" });

		if (userIndexData.projects && userIndexData.projects.length > 0) {
			for (const project of userIndexData.projects) {
				await storage.deleteProjectFile(project.id);
				await storage.deleteThumbnailFile(project.id);
			}
		}

		delete index.users[usernameLower];
		await storage.updateIndex(index);
		await storage.deleteUserJson(userIndexData.id);

		res.clearCookie("auth_token", {
			httpOnly: true,
			secure: true,
			sameSite: "none",
			path: "/"
		});

		res.status(200).json({ ok: true, message: "Goodbye :(" });
		sendEventMessage(`Account deleted: <b>${userIndexData.username}</b> (id ${userIndexData.id})`);
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});
