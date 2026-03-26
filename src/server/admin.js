import app from "../app.js";
import { securityCheck, verifyAuth } from "./helpers.js";
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
		if (role !== "dasher" || role !== "dasher+")
			return res.status(400).json({ ok: false, error: "Invalid role (allowed: dasher, dasher+)" });
		target.role = role;
	}

	const success = await updateUsersIndex(index);
	res.json({ ok: success });
});
