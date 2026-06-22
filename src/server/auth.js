import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import app from "../app.js";
import * as vars from "./vars.js";
import { isValidUsername, generateUserObject, securityCheck, verifyAuth, authLimiter, registerLimiter } from "./helpers.js";
import { uploadToTelegram, fetchFromTelegram, updateUsersIndex, editUserFile } from "./telegram.js";

app.get("/auth/verify-scratch", authLimiter, securityCheck, async (req, res) => {
	return res.status(200).send(`
		<script>
			window.opener.postMessage({ type: "verification_success", token: "noop" }, "https://dashblocks.github.io");
			window.opener.postMessage({ type: "verification_success", token: "noop" }, "${vars.SERVER_URL}");
			window.close();
		</script>
	`);
	// No more needed due to blocks in some countries
	// but leaving it here in case we need to re-enable
	// it in the future
	/* try {
		const { privateCode } = req.query;
		if (!privateCode)
			return res.status(400).json("<h1>Private code not found</h1>");

		const response = await fetch(`https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode=${privateCode}`);
		const data = await response.json();

		if (!data.valid || data.redirect !== `${vars.SERVER_URL}/auth/verify-scratch`)
			return res.status(400).json("<h1>Invalid private code :P</h1>");

		const scratchUsername = data.username;
		const token = jwt.sign(
			{ type: "scratch_verification", scratchUsername },
			vars.JWT_SCRATCH_VERIFY_SECRET,
			{ expiresIn: "5m" }
		);

		res.status(200).send(`
			<script>
				window.opener.postMessage({ type: "verification_success", token: "${token}" }, "https://dashblocks.github.io");
				window.opener.postMessage({ type: "verification_success", token: "${token}" }, "${vars.SERVER_URL}");
				window.close();
			</script>
		`);
	} catch (_) {
		res.status(500).send("<h1>Scratch Auth unavailable</h1>");
	} */
});

app.post("/auth/register", authLimiter, registerLimiter, securityCheck, async (req, res) => {
	try {
		// let scratchUsername;
		const { username, password /*, verificationToken */} = req.body;

		// Verification
		// For now, we are not verifying Scratch
		// accounts due to blocks in some countries
		// but we might re-enable it in the future
		/* if (!verificationToken)
			return res
				.status(400)
				.json({ ok: false, error: "Verification token not found" });
		let decoded;
		try {
			decoded = jwt.verify(verificationToken, vars.JWT_SCRATCH_VERIFY_SECRET);
			if (decoded.type !== "scratch_verification") throw new Error();
			scratchUsername = decoded.scratchUsername;
		} catch (_) {
			return res
				.status(400)
				.json({ ok: false, error: "Invalid verification token :P" });
		} */

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
		if (!password || password.length < 8 || password.length > 100)
			return res
				.status(400)
				.json({ ok: false, error: "Password must be 8-100 characters long" });

		const index = req.usersIndex;
		if (index.users[username.toLowerCase()])
			return res.status(400).json({ ok: false, error: "Username taken" });
		/* if (
			Object.values(index.users).some(
				(u) =>
					u.scratchUsername?.toLowerCase() === scratchUsername.toLowerCase()
			)
		)
			return res.status(400).json({
				ok: false,
				error: "This Scratch account is already linked to another user"
			}); */

		const hashedPassword = await bcrypt.hash(password, 12);
		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
		const userData = JSON.stringify({
			username,
			password: hashedPassword,
			ip: userIp
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
		await updateUsersIndex(index);

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
		let storedUser, user;
		const index = req.usersIndex;
		if (/^\d+$/.test(userId) && !userId.startsWith("0")) {
			// Likely ID
			const downloadUrl = await fetchFromTelegram(userId, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
			user = index.users[storedUser.username.toLowerCase()];
		} else {
			// Likely username
			user = index.users[userId.toLowerCase()];
			if (!user) throw new Error();
			const downloadUrl = await fetchFromTelegram(user.id, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
		}

		if (await bcrypt.compare(password, storedUser.password)) {
			user.ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
			user.lastActive = new Date().toISOString();
			await updateUsersIndex(index);
			const token = jwt.sign(
				{ userId: user.id, username: storedUser.username },
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
			res.json({ ok: true, userId: user.id, username: storedUser.username });
		} else {
			throw new Error();
		}
	} catch (_) {
		res.status(401).json({ ok: false, error: "Invalid target or password" });
	}
});

app.get("/session", verifyAuth, securityCheck, (req, res) => {
	const metadata = req.usersIndex.users[req.user.username.toLowerCase()];
	res.json({
		ok: true,
		user: {
			...generateUserObject(metadata),
			firedProjects: metadata?.firedProjects || null
		}
	});
});

app.get("/session/messages", verifyAuth, securityCheck, (req, res) => {
	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
	offset = isNaN(offset) ? 0 : Math.max(0, offset);

	const metadata = req.usersIndex.users[req.user.username.toLowerCase()];
	const messages = (metadata?.messages || []).slice(offset, offset + limit);
	res.json({
		ok: true,
		messages
	});
});

app.get("/session/activity", verifyAuth, securityCheck, async (req, res) => {
	try {
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];

		let activity = [];
		const following = user.following || [];

		for (const followed of following) {
			const followedData = index.users[followed.username.toLowerCase()];
			if (followedData && followedData.actions && followedData.actions.length > 0) {
				const userActions = followedData.actions.map(action => ({
					...action,
					author: {
						id: followedData.id,
						username: followedData.username,
						profile: {
							avatarId: followedData.avatarId
						}
					}
				}));
				activity.push(...userActions);
			}
		}

		activity.sort((a, b) => new Date(b.date) - new Date(a.date));

		activity = activity.slice(offset, offset + limit);

		res.json({
			ok: true,
			activity
		});
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
	res.clearCookie("scratch_verify_token", {
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

app.post("/auth/delete-account", verifyAuth, securityCheck, authLimiter, async (req, res) => {
	try {
		const { password } = req.body;
		if (!password)
			return res.status(400).json({ ok: false, error: "Password required" });

		const index = req.usersIndex;
		const userIndexData = index.users[req.user.username.toLowerCase()];
		if (!userIndexData)
			return res.status(404).json({ ok: false, error: "User not found" });

		const downloadUrl = await fetchFromTelegram(userIndexData.id, vars.USERS_GROUP_ID);
		const userFileRes = await fetch(downloadUrl);
		const storedUser = await userFileRes.json();

		if (!(await bcrypt.compare(password, storedUser.password)))
			return res.status(401).json({ ok: false, error: "Password is incorrect" });

		const success = await fetch(`${vars.TELEGRAM_API}/sendMessage`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				chat_id: vars.REQUESTS_GROUP_ID,
				text: `DELETE: User ${userIndexData.id} ${req.user.username}`
			})
		});
		if (!success)
			throw new Error("Failed to request deletion");

		res.clearCookie("auth_token", {
			httpOnly: true,
			secure: true,
			sameSite: "none",
			path: "/"
		});

		res.status(202).json({ ok: true, message: "Account deletion requested" });
	} catch (error) {
		res.status(500).json({ ok: false, error: error.message });
	}
});
