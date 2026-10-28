import app from "../app.js";
import { securityCheck, verifyAuth, sendEventMessage, eventFmt } from "./helpers.js";
import * as storage from "./storage.js";

app.post("/admin/manage-user", verifyAuth, securityCheck, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const { targetUsername, action, role, endDate } = req.body;
	const index = req.usersIndex;
	const target = index.users[targetUsername.toLowerCase()];

	if (!target)
		return res.status(404).json({ ok: false, error: "User not found" });

	if (target.role === "dashteam")
		return res.status(400).json({ ok: false, error: "User's role is Dash Team" });

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
		if (role !== "dasher" && role !== "dasher+" && role !== "dash-supporter")
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
