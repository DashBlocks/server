import bcrypt from "bcrypt";
import app from "../app.js";
import {
	ROLES,
	FORBIDDEN_USERNAMES
} from "./vars.js";
import {
	isValidEmail,
	isValidUsername,
	adminAccountUpdateLimiter,
	securityCheck,
	verifyAuth,
	sendEventMessage,
	eventFmt
} from "./util/helpers.js";
import * as storage from "./storage.js";

app.post("/admin/manage-user", adminAccountUpdateLimiter, verifyAuth, securityCheck, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const { targetUsername, action, role, endDate } = req.body || {};
	if (typeof targetUsername !== "string" || !targetUsername.trim() || typeof action !== "string")
		return res.status(400).json({ ok: false, error: "Target username and action required" });
	const index = req.usersIndex;
	const target = index.users[targetUsername.trim().toLowerCase()];

	if (!target)
		return res.status(404).json({ ok: false, error: "User not found" });

	if (target.role === "dashteam")
		return res.status(400).json({ ok: false, error: "User's role is Dash Team" });

	if (["update-account", "change-username", "change-email", "change-password"].includes(action)) {
		const username = action === "change-username" ? req.body.newUsername : req.body.username;
		const email = action === "change-email" ? req.body.newEmail : req.body.email;
		const password = action === "change-password" ? req.body.newPassword : req.body.password;
		const updateUsername = action === "change-username" || action === "update-account" && username !== undefined;
		const updateEmail = action === "change-email" || action === "update-account" && email !== undefined;
		const updatePassword = action === "change-password" || action === "update-account" && password !== undefined;

		if (!updateUsername && !updateEmail && !updatePassword)
			return res.status(400).json({ ok: false, error: "At least one account field is required" });
		if (updateUsername && (!isValidUsername(username) || FORBIDDEN_USERNAMES.includes(username.toLowerCase())))
			return res.status(400).json({ ok: false, error: "Invalid username" });
		if (updateEmail && (typeof email !== "string" || !isValidEmail(email)))
			return res.status(400).json({ ok: false, error: "Invalid email address" });
		if (updatePassword && (typeof password !== "string" || password.length < 8 || password.length > 100))
			return res.status(400).json({ ok: false, error: "Password must be 8-100 characters long" });

		const normalizedUsername = updateUsername ? username.trim().toLowerCase() : null;
		const normalizedEmail = updateEmail ? email.trim().toLowerCase() : null;
		if (updateUsername && Object.values(index.users).some(
			(user) => String(user.id) !== String(target.id) && user.username?.toLowerCase() === normalizedUsername
		)) return res.status(400).json({ ok: false, error: "Username taken" });
		if (updateEmail && Object.values(index.users).some(
			(user) => String(user.id) !== String(target.id) && user.email?.toLowerCase() === normalizedEmail
		)) return res.status(400).json({ ok: false, error: "Email already in use" });

		try {
			const storedUser = await storage.readUserJson(target.id);
			if (updateUsername) {
				const oldKey = target.username.toLowerCase();
				delete index.users[oldKey];
				target.username = username.trim();
				index.users[normalizedUsername] = target;
				for (const user of Object.values(index.users)) {
					for (const relation of [...(user.followers || []), ...(user.following || [])]) {
						if (String(relation.id) === String(target.id)) relation.username = target.username;
					}
				}
				for (const studio of Object.values(index.studios || {})) {
					if (String(studio.ownerId) === String(target.id)) studio.ownerUsername = target.username;
				}
				storedUser.username = target.username;
			}
			if (updateEmail) {
				target.email = email.trim();
				storedUser.email = email.trim();
			}
			if (updatePassword) {
				storedUser.password = await bcrypt.hash(password, 12);
			}
			await storage.updateUserJson(target.id, storedUser);
			await storage.updateIndex(index);
			res.json({ ok: true });
			sendEventMessage([
				"<b>#ADMIN #ACCOUNT_UPDATED</b>",
				eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
				eventFmt`target: ${{ type: "user", id: target.id, username: target.username }}`,
				`fields: <b>${[updateUsername && "username", updateEmail && "email", updatePassword && "password"].filter(Boolean).join(", ")}</b>`
			]);
		} catch (_) {
			res.status(500).json({ ok: false, error: "Failed to update user account" });
		}
		return;
	}

	if (action === "ban-user") {
		target.banned = true;
	} else if (action === "ban-ip") {
		if (target.ip && !index.bannedIps.includes(target.ip))
			index.bannedIps.push(target.ip);
	} else if (action === "unban-user") {
		target.banned = false;
	} else if (action === "unban-ip") {
		index.bannedIps = index.bannedIps.filter((ip) => ip !== target.ip);
	} else if (action === "promote" && role) {
		if (!ROLES.includes(role) || role === "dashteam")
			return res.status(400).json({ ok: false, error: "Invalid role (allowed: dasher, dasher+, dash-supporter)" });
		if (target.role === "dashteam")
			return res.status(400).json({ ok: false, error: "You can't demote Dash Team" });
		target.role = role;
		if (role === "dash-supporter")
			target.subscription = {
				status: "active",
				startDate: new Date().toISOString(),
				endDate: endDate ? new Date(endDate).toISOString() : "9999-01-01T00:00:00.000Z"
			};
		target.messages = [
			{
				type: "promoted",
				role,
				...(role === "dash-supporter" && {
					endDate: endDate ? new Date(endDate).toISOString() : "9999-01-01T00:00:00.000Z"
				}),
				date: new Date().toISOString()
			},
			...(target.messages || [])
		];
		target.unreadMessages = (target.unreadMessages || 0) + 1;
	} else {
		return res.status(400).json({ ok: false, error: "Action not found" });
	}

	try {
		await storage.updateIndex(index);
		res.json({ ok: true });

		const eventMessage = [
			"<b>#ADMIN #ADMIN_ACTION</b>",
			eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
			`action: <b>${action}</b>`,
			eventFmt`target: ${{ type: "user", id: target.id, username: target.username }}`
		];
		if (action === "promote") {
			eventMessage.push(`role: <b>${role}</b>`);
			if (role === "dash-supporter" && endDate) {
				eventMessage.push(`ends: <b><tg-time unix="${new Date(endDate).getTime()}" format="dT">${new Date(endDate).toISOString()}</tg-time></b>`);
			}
		}

		sendEventMessage(eventMessage);
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to update user index" });
	}
});

app.post("/admin/delete-account", verifyAuth, securityCheck, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const { username } = req.body;
	if (!username || typeof username !== "string")
		return res.status(400).json({ ok: false, error: "Username required" });

	const index = req.usersIndex;
	const userKey = username.toLowerCase();
	const userIndexData = index.users[userKey];

	if (!userIndexData)
		return res.status(404).json({ ok: false, error: "User not found" });

	if (userIndexData.role === "dashteam")
		return res.status(400).json({ ok: false, error: "User's role is Dash Team" });

	const userProjects = userIndexData.projects || [];
	for (const project of userProjects) {
		try {
			await storage.deleteProjectFile(project.id);
			if (project.thumbnailId && project.thumbnailId > 1) {
				await storage.deleteThumbnailFile(project.thumbnailId);
			}
		} catch (_) {/* ignore */}
	}

	try {
		await storage.deleteUserJson(userIndexData.id);
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to delete account" });
	}

	delete index.users[userKey];

	try {
		await storage.updateIndex(index);
		res.status(200).json({ ok: true, message: "Goodbye :(" });
		sendEventMessage([
			"<b>#ADMIN #ACCOUNT_DELETED</b>",
			eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
			eventFmt`target: ${{ type: "user", id: userIndexData.id, username }}`
		]);
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to delete account" });
	}
});
