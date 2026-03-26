import path from "path";
import { Readable } from "stream";

import app, { upload } from "../index";
import * as vars from "./vars";
import { securityCheck, verifyAuth } from "./helpers";
import { uploadToTelegram, fetchFromTelegram, updateUsersIndex } from "./telegram";

app.get("/users/:target", securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		let storedUser, indexData;
		if (/^\d+$/.test(target) && !target.startsWith("0")) {
			// Likely ID
			const downloadUrl = await fetchFromTelegram(target, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
			indexData = req.usersIndex.users[storedUser.username.toLowerCase()];
		} else {
			// Likely username
			indexData = req.usersIndex.users[target.toLowerCase()];
			const downloadUrl = await fetchFromTelegram(indexData.id, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			storedUser = await userFileRes.json();
		}

		res.json({
			ok: true,
			user: {
				id: indexData?.id || null,
				username: storedUser?.username || "Unknown",
				role: indexData?.role || "dasher",
				profile: {
					avatarId: indexData?.avatarId || 1,
					scratchUsername: indexData?.scratchUsername || null,
					description: indexData?.description || ""
				},
				joinedAt: indexData?.joinedAt || null,
				lastActive: indexData?.lastActive || null,
				projects: indexData?.projects || []
			}
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.post(
	"/users/upload-avatar",
	verifyAuth,
	securityCheck,
	upload.single("avatar"),
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({
				ok: false,
				error: "Must have Dasher+ role"
			});
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		const avatarId = await uploadToTelegram(
			vars.AVATARS_GROUP_ID,
			req.file.buffer,
			`avatar_${req.user.username}.png`
		);
		if (!avatarId)
			return res.status(500).json({ ok: false, error: "Upload failed" });

		const index = req.usersIndex;
		index.users[req.user.username.toLowerCase()].avatarId = avatarId;
		await updateUsersIndex(index);

		res.json({ ok: true, avatarId });
	}
);

app.get("/users/avatars/:id", async (req, res) => {
	try {
		const downloadUrl = await fetchFromTelegram(
			req.params.id,
			vars.AVATARS_GROUP_ID
		);
		const fileRes = await fetch(downloadUrl);

		res.setHeader("Content-Type", "image/png");
		Readable.fromWeb(fileRes.body).pipe(res);
	} catch (_) {
		res.setHeader("Content-Type", "image/png");
		res.status(200).sendFile(path.join(vars.ASSETS_PATH, "dasher-icon.png"));
	}
});

app.post(
	"/users/set-description",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({
				ok: false,
				error: "Must have Dasher+ role"
			});
		const description = req.body.description?.toString();
		if (!description)
			return res.status(400).json({
				ok: false,
				error: "No description provided"
			});

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		user.description = description;
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: {
				username: user.username,
				role: user?.role || "dasher",
				profile: {
					avatarId: user?.avatarId || 1,
					description: user?.description || ""
				},
				joinedAt: user?.joinedAt || null,
				lastActive: user?.lastActive || null,
				projects: user?.projects || []
			}
		});
	}
);
