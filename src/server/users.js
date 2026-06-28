import path from "path";
import jwt from "jsonwebtoken";

import app, { upload } from "../app.js";
import * as vars from "./vars.js";
import { generateUserObject, getUserIndexData, securityCheck, verifyAuth } from "./helpers.js";
import * as storage from "./storage.js";

app.get("/users/:target", securityCheck, async (req, res) => {
	try {
		const indexData = getUserIndexData(req.usersIndex, req.params.target);
		if (!indexData) throw new Error("User not found");

		let storedUser = {};
		try {
			storedUser = await storage.readUserJson(indexData.id);
		} catch (_) {/* ignore */}

		let user;
		const token = req.cookies.auth_token;
		try {
			if (token) {
				const decoded = jwt.verify(token, vars.JWT_SECRET);
				user = decoded;
			}
		} catch (_) {/* ignore */}

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
		const indexData = getUserIndexData(req.usersIndex, req.params.target);
		if (!indexData) throw new Error("User not found");

		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
        
		const projects = (indexData.projects || []).slice(offset, offset + limit).map(p => ({
			id: p?.id || null,
			name: p?.name || "Unknown",
			description: p?.description || "",
			stats: {
				fires: p?.stats?.fires || 0
			},
			thumbnailId: p?.id || 1
		}));

		res.json({ ok: true, projects });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/actions", securityCheck, async (req, res) => {
	try {
		const indexData = getUserIndexData(req.usersIndex, req.params.target);
		if (!indexData) throw new Error("User not found");

		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
        
		const actions = (indexData.actions || []).slice(offset, offset + limit);

		res.json({ ok: true, actions });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/followers", securityCheck, async (req, res) => {
	try {
		const indexData = getUserIndexData(req.usersIndex, req.params.target);
		if (!indexData) throw new Error("User not found");

		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);

		const followers = (indexData.followers || [])
			.slice(offset, offset + limit)
			.map(user => req.usersIndex.users[user.username.toLowerCase()])
			.filter(Boolean)
			.map(followerData => generateUserObject(followerData));

		res.json({ ok: true, followers });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.get("/users/:target/following", securityCheck, async (req, res) => {
	try {
		const indexData = getUserIndexData(req.usersIndex, req.params.target);
		if (!indexData) throw new Error("User not found");

		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);

		const following = (indexData.following || [])
			.slice(offset, offset + limit)
			.map(user => req.usersIndex.users[user.username.toLowerCase()])
			.filter(Boolean)
			.map(followingData => generateUserObject(followingData));

		res.json({ ok: true, following });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
});

app.post("/users/:target/follow", verifyAuth, securityCheck, async (req, res) => {
	try {
		const target = req.params.target;
		if (
			target.toLowerCase() === req.user.username.toLowerCase() ||
            (/^\d+$/.test(target) && !target.startsWith("0") && String(target) === String(req.user.userId))
		)
			return res.status(400).json({ ok: false, error: "Cannot follow yourself" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		const targetIndexData = getUserIndexData(index, target);
        
		if (!targetIndexData) return res.status(404).json({ ok: false, error: "User not found" });

		if (!user.following) user.following = [];
		if (!targetIndexData.followers) targetIndexData.followers = [];
		if (user.following.some(u => String(u.id) === String(targetIndexData.id)))
			return res.status(400).json({ ok: false, error: "Already following" });

		user.following.push({
			username: targetIndexData.username,
			id: targetIndexData.id
		});

		targetIndexData.followers.push({
			username: user.username,
			id: user.id
		});

		if ([1, 25, 50, 100].includes(targetIndexData.followers.length)) {
			targetIndexData.achievements = targetIndexData.achievements || [];
			targetIndexData.achievements.push({
				type: "reached-followers-count",
				count: targetIndexData.followers.length,
				date: new Date().toISOString()
			});
		}

		user.lastActive = new Date().toISOString();
		user.actions = user.actions || [];
		user.actions = [
			{
				type: "followed-user",
				user: {
					id: targetIndexData.id,
					username: targetIndexData.username
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
        
		await storage.updateIndex(index);

		res.json({ ok: true });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to follow user" });
	}
});

app.post("/users/:target/unfollow", verifyAuth, securityCheck, async (req, res) => {
	try {
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		const targetIndexData = getUserIndexData(index, req.params.target);

		if (!targetIndexData) return res.status(404).json({ ok: false, error: "User not found" });

		if (!user.following) user.following = [];
		if (!targetIndexData.followers) targetIndexData.followers = [];
		if (!user.following.some(u => String(u.id) === String(targetIndexData.id)))
			return res.status(400).json({ ok: false, error: "Not following" });

		user.following = user.following.filter(u => String(u.id) !== String(targetIndexData.id));
		targetIndexData.followers = targetIndexData.followers.filter(u => String(u.id) !== String(user.id));
        
		user.lastActive = new Date().toISOString();
		if (targetIndexData.messages) {
			targetIndexData.messages = targetIndexData.messages.filter(
				m => !(m.type === "new-follower" && String(m.user?.id) === String(user.id))
			);
		}
        
		await storage.updateIndex(index);

		res.json({ ok: true });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to unfollow user" });
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

		try {
			const index = req.usersIndex;
			const user = index.users[req.user.username.toLowerCase()];
			const avatarId = user.id; 
            
			await storage.saveAvatarFile(avatarId, req.file.buffer);

			user.avatarId = avatarId;
			user.lastActive = new Date().toISOString();
            
			await storage.updateIndex(index);

			res.json({ ok: true, avatarId });
		} catch (_) {
			res.status(500).json({ ok: false, error: "Upload failed" });
		}
	}
);

app.get("/users/avatars/:id", async (req, res) => {
	try {
		const avatarId = req.params.id;
		const exists = await storage.avatarFileExists(avatarId);

		if (!exists) throw new Error("Avatar not found");

		res.setHeader("Content-Type", "image/png");
		res.sendFile(path.join(vars.DATA_USERS_PATH, String(avatarId), `${avatarId}.png`));
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
			return res.status(403).json({ ok: false, error: "Must have Dasher+ role" });
            
		const description = req.body.description?.toString();
		if (!description) return res.status(400).json({ ok: false, error: "No description provided" });
		if (description.length > 1000) return res.status(400).json({ ok: false, error: "Max length is 1000" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		user.description = description;
		user.lastActive = new Date().toISOString();
        
		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);

app.post(
	"/users/set-gradient",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole !== "dash-supporter" && req.userRole !== "dashteam")
			return res.status(403).json({ ok: false, error: "Must have Dash Supporter role" });

		const gradientValue = req.body.gradient;
		// eslint-disable-next-line
		let normalizedGradient = null;

		if (gradientValue === "" || gradientValue === null || gradientValue === undefined) {
			normalizedGradient = null;
		} else if (typeof gradientValue !== "object" || Array.isArray(gradientValue)) {
			return res.status(400).json({ ok: false, error: "Gradient must be an object or null" });
		} else {
			const { type, angle, stops } = gradientValue;
			if (type !== "linear") {
				return res.status(400).json({ ok: false, error: "Gradient type must be 'linear'" });
			}
			if (typeof angle !== "number" || angle < 0 || angle > 360) {
				return res.status(400).json({ ok: false, error: "Angle must be a number between 0 and 360" });
			}
			if (!Array.isArray(stops) || stops.length < 2 || stops.length > 6) {
				return res.status(400).json({ ok: false, error: "Gradient stops must be an array of 2 to 6 stops" });
			}
			const colorRegex = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
			const positionRegex = /^(?:100|[1-9]?\d)%$/;
			for (const stop of stops) {
				if (!stop || typeof stop !== "object") {
					return res.status(400).json({ ok: false, error: "Each gradient stop must be an object" });
				}
				if (!colorRegex.test(stop.color)) {
					return res.status(400).json({ ok: false, error: "Each gradient stop color must be a valid hex code" });
				}
				if (!positionRegex.test(stop.position)) {
					return res.status(400).json({ ok: false, error: "Each gradient stop position must be a percentage between 0% and 100%" });
				}
			}
			normalizedGradient = {
				type: "linear",
				angle,
				stops: stops.map((stop) => ({ color: stop.color.toLowerCase(), position: stop.position }))
			};
		}

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];

		user.gradient = normalizedGradient;
		user.lastActive = new Date().toISOString();

		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);

app.post(
	"/users/set-recommended-project",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		const projectId = Number(req.body.projectId);
		if (!projectId) return res.status(400).json({ ok: false, error: "No project ID provided" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
		const projectMeta = user.projects.find(p => String(p.id) === String(projectId));
        
		if (!projectMeta)
			return res.status(404).json({ ok: false, error: "Project not found in your profile" });
            
		user.recommendedProject = {
			id: projectId,
			name: projectMeta.name,
			thumbnailId: projectId
		};
		user.lastActive = new Date().toISOString();
        
		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);

app.post(
	"/users/add-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({ ok: false, error: "Must have Dasher+ role" });
            
		const { label, link } = req.body;
		if (!link) return res.status(400).json({ ok: false, error: "No link provided" });
		if (link.length > 200) return res.status(400).json({ ok: false, error: "Link max length is 200" });
		if (label && label.length > 50) return res.status(400).json({ ok: false, error: "Label max length is 50" });
		if (!/^https?:\/\//.test(link)) return res.status(400).json({ ok: false, error: "Invalid link" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		if (!user.links) user.links = [];
		if (user.links.length === 5) return res.status(400).json({ ok: false, error: "Max links count is 5" });
        
		user.links.push({ label: label || "Link", link });
		user.lastActive = new Date().toISOString();
        
		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);

app.post(
	"/users/update-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({ ok: false, error: "Must have Dasher+ role" });
            
		const { linkIndex, label, link } = req.body;
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		if ((!linkIndex && linkIndex !== 0) || !link)
			return res.status(400).json({ ok: false, error: "No link provided" });
		if (link.length > 200) return res.status(400).json({ ok: false, error: "Link max length is 200" });
		if (label && label.length > 50) return res.status(400).json({ ok: false, error: "Label max length is 50" });
		if (!/^https?:\/\//.test(link)) return res.status(400).json({ ok: false, error: "Invalid link" });

		if (!user.links || !user.links[linkIndex])
			return res.status(400).json({ ok: false, error: "Link not found" });
            
		user.links[linkIndex] = { label: label || "Link", link };
		user.lastActive = new Date().toISOString();
        
		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);

app.post(
	"/users/remove-link",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole === "dasher")
			return res.status(403).json({ ok: false, error: "Must have Dasher+ role" });
            
		const linkIndex = req.body.linkIndex;
		if (!linkIndex && linkIndex !== 0) return res.status(400).json({ ok: false, error: "No link provided" });

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		if (!user.links || !user.links[linkIndex])
			return res.status(400).json({ ok: false, error: "Link not found" });
            
		user.links.splice(linkIndex, 1);
		user.lastActive = new Date().toISOString();
        
		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user) });
	}
);
