import app from "../app.js";
import { securityCheck, verifyAuth } from "./helpers.js";
import * as vars from "./vars.js";
import { updateUsersIndex } from "./telegram.js";

app.post("/admin/manage-user", verifyAuth, securityCheck, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const { targetUsername, action, role } = req.body;
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
		if (role !== "dasher" && role !== "dasher+")
			return res.status(400).json({ ok: false, error: "Invalid role (allowed: dasher, dasher+)" });
		if (target.role === "dashteam")
			return res.status(400).json({ ok: false, error: "You can't demote Dash Team" });
		target.role = role;
		target.messages = [
			{
				type: "promoted",
				role,
				date: new Date().toISOString()
			},
			...(target.messages || [])
		];
	} else {
		return res.status(400).json({ ok: false, error: "Action not found" });
	}

	const success = await updateUsersIndex(index);
	res.json({ ok: success });
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
	const userIndexData = index.users[username.toLowerCase()];
	if (!userIndexData)
		return res.status(404).json({ ok: false, error: "User not found" });

	if (userIndexData.role === "dashteam")
		return res.status(400).json({ ok: false, error: "User's role is Dash Team" });

	const reqRes = await fetch(`${vars.TELEGRAM_API}/sendMessage`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			chat_id: vars.REQUESTS_GROUP_ID,
			text: `DELETE by Admin: User ${userIndexData.username} (${userIndexData.id})\nBy: ${req.user.username} (${req.user.userId})`
		})
	});
	if (!reqRes.ok)
		return res.status(500).json({ ok: false, error: "Failed to delete account" });

	delete index.users[username.toLowerCase()];
	if (!await updateUsersIndex(index))
		return res.status(500).json({ ok: false, error: "Failed to delete account" });

	res.status(202).json({ ok: true, error: "Removed from index, file deletion requested" });
});
