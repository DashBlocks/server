import path from "path";
import jwt from "jsonwebtoken";
import { Readable } from "stream";

import app, { upload } from "../app.js";
import * as vars from "./vars.js";
import { generateUserObject, securityCheck, verifyAuth } from "./helpers.js";
import { uploadToTelegram, fetchFromTelegram, updateUsersIndex } from "./telegram.js";

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

		let user;
		const token = req.cookies.auth_token;
		try {
			const decoded = jwt.verify(token, vars.JWT_SECRET);
			user = decoded;
		} catch (_) {}

		res.json({
			ok: true,
			user: {
				...generateUserObject({ ...storedUser, ...indexData }),
				isFollowing: user ? (indexData.followers?.some(f => String(f.id) === String(user.userId)) || false) : false
			}
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/projects", securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
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
		}

		const projects = (indexData.projects || []).slice(offset, offset + limit).map(p => ({
			id: p?.id || null,
			name: p?.name || "Unknown",
			description: p?.description || "",
			stats: {
				fires: p?.stats?.fires || 0
			},
			thumbnailId: p?.thumbnailId || 1
		}));

		res.json({
			ok: true,
			projects
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/actions", securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
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
		}

		const actions = (indexData.actions || []).slice(offset, offset + limit);

		res.json({
			ok: true,
			actions
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/followers", securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
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
		}

		const followers = (indexData.followers || []).slice(offset, offset + limit).map(user => {
			const followerData = req.usersIndex.users[user.username.toLowerCase()];
			return generateUserObject(followerData);
		});

		res.json({
			ok: true,
			followers
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/following", securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
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
		}

		const following = (indexData.following || []).slice(offset, offset + limit).map(user => {
			const followingData = req.usersIndex.users[user.username.toLowerCase()];
			return generateUserObject(followingData);
		});

		res.json({
			ok: true,
			following
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.post("/users/:target/follow", verifyAuth, securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		if (
			target.toLowerCase() === req.user.username.toLowerCase() ||
			/^\d+$/.test(target) && !target.startsWith("0") && String(target) === String(req.user.userId)
		)
			return res.status(400).json({ ok: false, error: "Cannot follow yourself" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		let targetUser, targetIndexData;
		if (/^\d+$/.test(target) && !target.startsWith("0")) {
			// Likely ID
			const downloadUrl = await fetchFromTelegram(target, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			targetUser = await userFileRes.json();
			targetIndexData = index.users[targetUser.username.toLowerCase()];
		} else {
			// Likely username
			targetIndexData = index.users[target.toLowerCase()];
			const downloadUrl = await fetchFromTelegram(targetIndexData.id, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			targetUser = await userFileRes.json();
		}

		if (!targetIndexData || !targetUser)
			return res.status(404).json({ ok: false, error: "User not found" });

		if (!user.following) user.following = [];
		if (!targetIndexData.followers) targetIndexData.followers = [];
		if (user.following.find(u => String(u.id) === String(targetIndexData.id)))
			return res.status(400).json({ ok: false, error: "Already following" });

		user.following.push({
			username: targetUser.username,
			id: targetIndexData.id
		});

		targetIndexData.followers.push({
			username: user.username,
			id: index.users[user.username.toLowerCase()].id
		});

		if (targetIndexData.followers.length === 1)
			targetIndexData.achievements.push({
				type: "reached-followers-count",
				count: targetIndexData.followers.length,
				date: new Date().toISOString()
			});

		if (targetIndexData.followers.length === 25)
			targetIndexData.achievements.push({
				type: "reached-followers-count",
				count: targetIndexData.followers.length,
				date: new Date().toISOString()
			});

		if (targetIndexData.followers.length === 50)
			targetIndexData.achievements.push({
				type: "reached-followers-count",
				count: targetIndexData.followers.length,
				date: new Date().toISOString()
			});

		if (targetIndexData.followers.length === 100)
			targetIndexData.achievements.push({
				type: "reached-followers-count",
				count: targetIndexData.followers.length,
				date: new Date().toISOString()
			});

		user.lastActive = new Date().toISOString();
		user.actions = user.actions || [];
		user.actions = [
			{
				type: "followed-user",
				user: {
					id: targetIndexData.id,
					username: targetUser.username
				},
				date: new Date().toISOString()
			},
			...user.actions
		];
		targetIndexData.messages = [
			{
				type: "new-follower",
				user: {
					id: user.id,
					username: user.username
				},
				date: new Date().toISOString()
			},
			...(targetIndexData.messages || [])
		];
		await updateUsersIndex(index);

		res.json({ ok: true });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.post("/users/:target/unfollow", verifyAuth, securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		let targetUser, targetIndexData;
		if (/^\d+$/.test(target) && !target.startsWith("0")) {
			// Likely ID
			const downloadUrl = await fetchFromTelegram(target, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			targetUser = await userFileRes.json();
			targetIndexData = index.users[targetUser.username.toLowerCase()];
		} else {
			// Likely username
			targetIndexData = index.users[target.toLowerCase()];
			const downloadUrl = await fetchFromTelegram(targetIndexData.id, vars.USERS_GROUP_ID);
			const userFileRes = await fetch(downloadUrl);
			targetUser = await userFileRes.json();
		}

		if (!targetIndexData || !targetUser)
			return res.status(404).json({ ok: false, error: "User not found" });

		if (!user.following) user.following = [];
		if (!targetIndexData.followers) targetIndexData.followers = [];
		if (!user.following.find(u => String(u.id) === String(targetIndexData.id)))
			return res.status(400).json({ ok: false, error: "Not following" });

		user.following.splice(user.following.findIndex(u => String(u.id) === String(targetIndexData.id)), 1);
		targetIndexData.followers.splice(targetIndexData.followers.findIndex(u => u.username.toLowerCase() === user.username.toLowerCase()), 1);
		user.lastActive = new Date().toISOString();
		if (targetIndexData.messages)
			targetIndexData.messages = targetIndexData.messages.filter(m => !(m.type === "new-follower" && m.user.username.toLowerCase() === user.username.toLowerCase()));
		await updateUsersIndex(index);

		res.json({ ok: true });
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
		const user = index.users[req.user.username.toLowerCase()];
		user.avatarId = avatarId;
		user.lastActive = new Date().toISOString();
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

		if (description.length > 1000)
			return res.status(400).json({
				ok: false,
				error: "Max length is 1000"
			});

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		user.description = description;
		user.lastActive = new Date().toISOString();
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: generateUserObject(user)
		});
	}
);

app.post(
	"/users/set-recommended-project",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		const projectId = Number(req.body.projectId);
		if (!projectId)
			return res.status(400).json({
				ok: false,
				error: "No project ID provided"
			});

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		const projectMeta = user.projects.find(p => String(p.id) === String(projectId));
		if (!projectMeta)
			return res.status(404).json({
				ok: false,
				error: "Project not found in your profile"
			});
		user.recommendedProject = {
			id: projectId,
			name: projectMeta.name,
			thumbnailId: projectMeta.thumbnailId
		};
		user.lastActive = new Date().toISOString();
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: generateUserObject(user)
		});
	}
);

app.post(
	"/users/add-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({
				ok: false,
				error: "Must have Dasher+ role"
			});
		const { label, link } = req.body;
		if (!link)
			return res.status(400).json({
				ok: false,
				error: "No link provided"
			});
		if (link.length > 200)
			return res.status(400).json({
				ok: false,
				error: "Link max length is 200"
			});
		if (label && label.length > 50)
			return res.status(400).json({
				ok: false,
				error: "Label max length is 50"
			});
		if (!/^https?:\/\//.test(link))
			return res.status(400).json({
				ok: false,
				error: "Invalid link"
			});

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		if (!user.links) user.links = [];
		if (user.links.length === 5)
			return res.status(400).json({
				ok: false,
				error: "Max links count is 5"
			});
		user.links.push({
			label: label || "Link",
			link
		});
		user.lastActive = new Date().toISOString();
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: generateUserObject(user)
		});
	}
);

app.post(
	"/users/update-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({
				ok: false,
				error: "Must have Dasher+ role"
			});
		const { linkIndex, label, link } = req.body;
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		if ((!linkIndex && linkIndex !== 0) || !link)
			return res.status(400).json({
				ok: false,
				error: "No link provided"
			});
		if (link.length > 200)
			return res.status(400).json({
				ok: false,
				error: "Link max length is 200"
			});
		if (label && label.length > 50)
			return res.status(400).json({
				ok: false,
				error: "Label max length is 50"
			});
		if (!/^https?:\/\//.test(link))
			return res.status(400).json({
				ok: false,
				error: "Invalid link"
			});

		if (!user.links || !user.links[linkIndex])
			return res.status(400).json({
				ok: false,
				error: "Link not found"
			});
		user.links[linkIndex] = {
			label: label || "Link",
			link
		};
		user.lastActive = new Date().toISOString();
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: generateUserObject(user)
		});
	}
);

app.post(
	"/users/remove-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({
				ok: false,
				error: "Must have Dasher+ role"
			});
		const linkIndex = req.body.linkIndex;
		if (!linkIndex && linkIndex !== 0)
			return res.status(400).json({
				ok: false,
				error: "No link provided"
			});

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		if (!user.links || !user.links[linkIndex])
			return res.status(400).json({
				ok: false,
				error: "Link not found"
			});
		user.links.splice(linkIndex, 1);
		user.lastActive = new Date().toISOString();
		await updateUsersIndex(index);

		res.json({
			ok: true,
			user: generateUserObject(user)
		});
	}
);
