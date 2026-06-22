import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import app from "../app.js";
import * as vars from "./vars.js";
import { isValidUsername, generateUserObject, securityCheck, verifyAuth, authLimiter, registerLimiter } from "./helpers.js";
import * as storage from "./storage.js";

app.post("/auth/register", authLimiter, registerLimiter, securityCheck, async (req, res) => {
	try {
		const { username, password } = req.body;

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

		const index = await storage.getIndex();
		if (index.users[username.toLowerCase()])
			return res.status(400).json({ ok: false, error: "Username taken" });

		const hashedPassword = await bcrypt.hash(password, 12);
		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
        
		const userId = index.nextUserId;

		const newUserMetadata = {
			id: userId,
			username,
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
			achievements: []
		};

		const userData = { username, password: hashedPassword, ip: userIp };
		await storage.createUserJson(userId, userData);

		index.users[username.toLowerCase()] = newUserMetadata;
		index.nextUserId++;
		await storage.updateIndex(index);

		const token = jwt.sign({ userId, username }, vars.JWT_SECRET, {
			expiresIn: "7d"
		});
		res.cookie("auth_token", token, {
			httpOnly: true,
			secure: true,
			sameSite: "none",
			maxAge: 7 * 24 * 60 * 60 * 1000,
			path: "/"
		});

		res.json({ ok: true, userId, username });
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});

app.post("/auth/login", authLimiter, securityCheck, async (req, res) => {
	try {
		const { userId, password } = req.body;
		const index = await storage.getIndex();
        
		let user;
		if (/^\d+$/.test(userId)) {
			user = storage.findUserById(index, userId);
		} else {
			user = index.users[userId.toLowerCase()];
		}
		if (!user) throw new Error();

		const storedUser = await storage.readUserJson(user.id);

		if (await bcrypt.compare(password, storedUser.password)) {
			user.ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
			user.lastActive = new Date().toISOString();
			await storage.updateIndex(index);
            
			const token = jwt.sign({ userId: user.id, username: user.username }, vars.JWT_SECRET, { expiresIn: "7d" });
            
			res.cookie("auth_token", token, { httpOnly: true, secure: true, sameSite: "none", maxAge: 7 * 24 * 60 * 60 * 1000, path: "/" });
			res.json({ ok: true, userId: user.id, username: user.username });
		} else {
			throw new Error();
		}
	} catch (_) {
		res.status(401).json({ ok: false, error: "Invalid target or password" });
	}
});

app.get("/session", verifyAuth, securityCheck, async (req, res) => {
	const index = await storage.getIndex();
	const metadata = index.users[req.user.username.toLowerCase()];
	res.json({
		ok: true,
		user: { ...generateUserObject(metadata), firedProjects: metadata?.firedProjects || null }
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
							avatarId: followedData.avatarId
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
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});
