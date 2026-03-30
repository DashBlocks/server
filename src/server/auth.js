import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import app from "../app.js";
import * as vars from "./vars.js";
import { isValidUsername, securityCheck, verifyAuth, authLimiter } from "./helpers.js";
import { uploadToTelegram, fetchFromTelegram, updateUsersIndex, editUserFile } from "./telegram.js";

app.get("/auth/get-auth-code", authLimiter, securityCheck, (_, res) => {
	const arr = new Uint8Array(50);
	crypto.getRandomValues(arr);
	const code = Array.from(arr)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	const token = jwt.sign(
		{ code, type: "register_verification" },
		vars.JWT_VERIFY_SECRET,
		{
			expiresIn: "5m"
		}
	);
	res.cookie("verification_token", token, {
		httpOnly: true,
		secure: true,
		sameSite: "none",
		maxAge: 5 * 60 * 1000,
		path: "/"
	});

	res.json({ ok: true, code });
});

app.post("/auth/register", authLimiter, securityCheck, async (req, res) => {
	try {
		const { scratchUsername, username, password } = req.body;

		// Verification

		const verifyToken = req.cookies.verification_token;
		if (!verifyToken)
			return res
				.status(400)
				.json({ ok: false, error: "Verification token not found" });
		let decoded;
		try {
			decoded = jwt.verify(verifyToken, vars.JWT_VERIFY_SECRET);
			if (decoded.type !== "register_verification") throw new Error();
		} catch (_) {
			return res
				.status(400)
				.json({ ok: false, error: "Invalid verification token :P" });
		}

		const commentsRes = await fetch(
			"https://api.scratch.mit.edu/users/Dash_Blocks/projects/1288539368/comments?limit=20"
		);
		if (!commentsRes.ok)
			return res
				.status(400)
				.json({ ok: false, error: "Failed to verify user" });
		const comments = await commentsRes.json();

		const isVerified = comments.some(
			(c) =>
				c.author.username.toLowerCase() === scratchUsername.toLowerCase() &&
				c.content.includes(decoded.code)
		);

		if (!isVerified) {
			return res.status(401).json({
				ok: false,
				error: "Your verification token not found on project"
			});
		}

		// Account creation

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
		if (!password || (password.length < 8 && password.length > 100))
			return res
				.status(400)
				.json({ ok: false, error: "Password must be 8-100 characters long" });

		const index = req.usersIndex;
		if (index.users[username.toLowerCase()])
			return res.status(400).json({ ok: false, error: "Username taken" });
		if (
			Object.values(index.users).some(
				(u) =>
					u.scratchUsername?.toLowerCase() === scratchUsername.toLowerCase()
			)
		)
			return res.status(400).json({
				ok: false,
				error: "This Scratch account is already linked to another user"
			});

		const hashedPassword = await bcrypt.hash(password, 12);
		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
		const userData = JSON.stringify({
			username,
			scratchUsername,
			password: hashedPassword,
			ip: userIp,
			banned: false
		});

		const userId = await uploadToTelegram(
			vars.USERS_GROUP_ID,
			Buffer.from(userData),
			`${username}.json`
		);
		if (!userId) throw new Error("Failed to create user");

		index.users[username.toLowerCase()] = {
			id: userId,
			username,
			scratchUsername,
			role: "dasher",
			banned: false,
			ip: userIp,
			description: "",
			avatarId: 1,
			projects: [],
			firedProjects: [],
			joinedAt: new Date().toISOString(),
			lastActive: new Date().toISOString()
		};
		await updateUsersIndex(index);

		res.clearCookie("verification_token");

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
		let storedUser, indexData;
		if (/^\d+$/.test(userId) && !userId.startsWith("0")) {
			// Likely ID
			const downloadUrl = await fetchFromTelegram(userId, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
			indexData = req.usersIndex.users[storedUser.username.toLowerCase()];
		} else {
			// Likely username
			indexData = req.usersIndex.users[userId.toLowerCase()];
			const downloadUrl = await fetchFromTelegram(indexData.id, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
		}

		if (await bcrypt.compare(password, storedUser.password)) {
			const token = jwt.sign(
				{ userId: storedUser.userId, username: storedUser.username },
				vars.JWT_SECRET,
				{ expiresIn: "7d" }
			);
			res.cookie("auth_token", token, {
				httpOnly: true,
				secure: true,
				sameSite: "none",
				maxAge: 7 * 24 * 60 * 60 * 1000,
				path: "/"
			});
			res.json({ ok: true, username: storedUser.username, userId: storedUser.userId });
		} else {
			res.status(401).json({ ok: false, error: "Invalid target or password" });
		}
	} catch (_) {
		res.status(401).json({ ok: false, error: "Invalid target or password" });
	}
});

app.get("/session", verifyAuth, securityCheck, (req, res) => {
	const metadata = req.usersIndex.users[req.user.username.toLowerCase()];
	res.json({
		ok: true,
		userId: Number(req.user.userId),
		username: req.user.username,
		role: metadata?.role || "dasher",
		profile: {
			avatarId: metadata?.avatarId || 1,
			description: metadata?.description || ""
		},
		joinedAt: metadata?.joinedAt || null,
		lastActive: metadata?.lastActive || null,
		projects: metadata?.projects || []
	});
});

app.get("/auth/logout", verifyAuth, (req, res) => {
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

		const index = req.usersIndex;
		const userIndexData = index.users[req.user.username.toLowerCase()];
		if (!userIndexData)
			return res.status(404).json({ ok: false, error: "User not found" });

		const downloadUrl = await fetchFromTelegram(userIndexData.id, vars.USERS_GROUP_ID);
		const userFileRes = await fetch(downloadUrl);
		const storedUser = await userFileRes.json();

		if (!(await bcrypt.compare(currentPassword, storedUser.password)))
			return res.status(401).json({ ok: false, error: "Current password is incorrect" });

		storedUser.password = await bcrypt.hash(newPassword, 12);

		const success = await editUserFile(
			userIndexData.id,
			Buffer.from(JSON.stringify(storedUser)),
			`${storedUser.username}.json`
		);
		if (!success)
			throw new Error("Failed to update password");

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
