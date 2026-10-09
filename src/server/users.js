import path from "path";
import jwt from "jsonwebtoken";

import app, { imageUpload } from "../app.js";
import * as vars from "./vars.js";
import {
	generateUserObject,
	getProjectStudiosCount,
	getUserIndexData,
	securityCheck,
	verifyAuth,
	uploadLimiter,
	avatarUploadTimeout,
	escapeHTML,
	sendEventMessage,
	eventFmt
} from "./helpers.js";
import { formatAvatarImage } from "./image-processing.js";
import * as storage from "./storage.js";

const getUserFormattedData = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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
				if (decoded.tokenType === "access") user = decoded;
			}
		} catch (_) {/* ignore */}

		res.json({
			ok: true,
			user: {
				...generateUserObject({ ...storedUser, ...indexData }, req.usersIndex),
				isFollowing: user ? (indexData.followers?.some(f => String(f.id) === String(user.userId)) || false) : false
			}
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
};
app.get("/users/profiles/:target", securityCheck, getUserFormattedData(false));
app.get("/users/:target", securityCheck, getUserFormattedData(true));

const getUserProjects = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
	try {
		const author = getUserIndexData(req.usersIndex, req.params.target);
		if (!author) throw new Error("User not found");

		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
		offset = isNaN(offset) ? 0 : Math.max(0, offset);

		const projects = (author.projects?.toReversed() || []).slice(offset, offset + limit).map(p => ({
			id: p?.id || null,
			name: p?.name || "Unknown",
			description: p?.description || "",
			thumbnailId: p?.id || 1,
			stats: {
				views: p?.stats?.views || 0,
				fires: p?.stats?.fires || 0,
				forks: p?.stats?.forks || 0,
				studios: getProjectStudiosCount(req.usersIndex, p?.id)
			},
			author: {
				id: author.id || null,
				username: author.username || "Unknown",
				role: author.role || "dasher",
				profile: { avatarId: author.id || 1 },
				joinedAt: author.joinedAt || null,
				lastActive: author.lastActive || null
			}
		}));

		res.json({
			ok: true,
			total: (author.projects?.toReversed() || []).length,
			projects
		});
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
};
app.get("/users/profiles/:target/projects", securityCheck, getUserProjects(false));
app.get("/users/:target/projects", securityCheck, getUserProjects(true));

const getUserStudios = (isDeprecatedPath) => (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
	const index = req.usersIndex;
	const user = getUserIndexData(index, req.params.target);
	if (!user) return res.status(404).json({ ok: false, error: "User not found" });

	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = Number.isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = Number.isNaN(offset) ? 0 : Math.max(0, offset);
	const studios = Object.values(index.studios || {}).toReversed()
		.filter((studio) => String(studio.ownerId) === String(user.id));
	const formattedStudios = studios
		.slice(offset, offset + limit)
		.map((studio) => ({
			id: studio.id,
			owner: generateUserObject(user, index),
			name: studio.name || "Untitled Studio",
			description: studio.description || "",
			allowProjects: !!studio.allowProjects,
			projectsCount: (studio.projects || []).length,
			thumbnailId: studio.id || 1,
			createdAt: studio.createdAt || null,
			updatedAt: studio.updatedAt || null
		}));

	res.json({
		ok: true,
		total: studios.length,
		studios: formattedStudios
	});
};
app.get("/users/profiles/:target/studios", securityCheck, getUserStudios(false));
app.get("/users/:target/studios", securityCheck, getUserStudios(true));

const getUserActions = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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
};
app.get("/users/profiles/:target/actions", securityCheck, getUserActions(false));
app.get("/users/:target/actions", securityCheck, getUserActions(true));

const getUserFollowers = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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
			.map(followerData => generateUserObject(followerData, req.usersIndex));

		res.json({ ok: true, followers });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
};
app.get("/users/profiles/:target/followers", securityCheck, getUserFollowers(false));
app.get("/users/:target/followers", securityCheck, getUserFollowers(true));

const getUserFollowing = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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
			.map(followingData => generateUserObject(followingData, req.usersIndex));

		res.json({ ok: true, following });
	} catch (_) {
		res.status(404).json({ ok: false, error: "User not found" });
	}
};
app.get("/users/profiles/:target/following", securityCheck, getUserFollowing(false));
app.get("/users/:target/following", securityCheck, getUserFollowing(true));

const followUser = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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

		if ([1, 25, 50, 100, 250, 500, 1000, 5000, 10000].includes(targetIndexData.followers.length)) {
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
		targetIndexData.unreadMessages = (targetIndexData.unreadMessages || 0) + 1;

		await storage.updateIndex(index);

		res.json({ ok: true });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to follow user" });
	}
};
app.post("/users/profiles/:target/follow", verifyAuth, securityCheck, followUser(false));
app.post("/users/:target/follow", verifyAuth, securityCheck, followUser(true));

const unfollowUser = (isDeprecatedPath) => async (req, res) => {
	if (isDeprecatedPath) {
		res.setHeader("Deprecation", "@<1791549156>")
	}
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
			targetIndexData.unreadMessages = (targetIndexData.unreadMessages || 1) - 1;
		}

		await storage.updateIndex(index);

		res.json({ ok: true });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to unfollow user" });
	}
};
app.post("/users/profiles/:target/unfollow", verifyAuth, securityCheck, unfollowUser(false));
app.post("/users/:target/unfollow", verifyAuth, securityCheck, unfollowUser(true));

app.post(
	"/users/upload-avatar",
	verifyAuth,
	securityCheck,
	uploadLimiter,
	avatarUploadTimeout,
	imageUpload.single("avatar"),
	async (req, res) => {
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		try {
			const index = req.usersIndex;
			const user = index.users[req.user.username.toLowerCase()];
			const avatarId = user.id;
			const formatted = await formatAvatarImage(req.file.buffer);

			await storage.saveAvatarFile(avatarId, formatted);

			user.avatarId = avatarId;
			user.lastActive = new Date().toISOString();

			await storage.updateIndex(index);

			res.json({ ok: true, avatarId });
			sendEventMessage([
				"<b>#USER_AVATAR_UPDATED</b>",
				eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`,
				`avatar: <b>${avatarId}</b>`
			]);
		} catch (error) {
			if (error?.message === "Invalid image file" || error?.message === "Format not supported") {
				return res.status(400).json({ ok: false, error: error.message });
			}
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
		if (typeof description !== "string") return res.status(400).json({ ok: false, error: "No description provided" });
		if (description.length > 1000) return res.status(400).json({ ok: false, error: "Max length is 1000" });

		const index = req.usersIndex;
		const isDashTeam = req.userRole === "dashteam";
		const user = isDashTeam && req.query?.target ? index.users[req.query.target.toLowerCase()] : index.users[req.user.username.toLowerCase()];
		if (!user)
			return res.status(404).json({ ok: false, error: "User not found" });

		user.description = description;
		user.lastActive = new Date().toISOString();

		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
		if (isDashTeam && req.user.userId !== user.id) {
			sendEventMessage([
				"<b>#ADMIN #USER_DESCRIPTION_UPDATED</b>",
				eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
				eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`
			]);
		} else {
			sendEventMessage([
				"<b>#USER_DESCRIPTION_UPDATED</b>",
				eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`
			]);
		}
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

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
	}
);

app.post(
	"/users/set-avatar-frame",
	verifyAuth,
	securityCheck,
	async (req, res) => {
		if (req.userRole !== "dash-supporter" && req.userRole !== "dashteam")
			return res.status(403).json({ ok: false, error: "Must have Dash Supporter role" });

		const avatarFrameValue = req.body.avatarFrame;
		// eslint-disable-next-line
		let avatarFrame = null;

		if (avatarFrameValue === "" || avatarFrameValue === null || avatarFrameValue === undefined) {
			avatarFrame = null;
		} else if (!vars.AVATAR_FRAMES.includes(avatarFrameValue)) {
			return res.status(400).json({ ok: false, error: "Frame not exist" });
		} else {
			avatarFrame = avatarFrameValue;
		}

		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];

		user.avatarFrame = avatarFrame;
		user.lastActive = new Date().toISOString();

		await storage.updateIndex(index);

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
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

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
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

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
		sendEventMessage([
			"<b>#USER_LINK_ADDED</b>",
			eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`,
			`link: <b>${escapeHTML(label)}</b> (<a href="${escapeHTML(link)}">link...</a>)`
		]);
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

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
		sendEventMessage([
			"<b>#USER_LINK_UPDATED</b>",
			eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`,
			`idx: ${linkIndex + 1}`,
			`link: <b>${escapeHTML(label)}</b> (<a href="${escapeHTML(link)}">link...</a>)`
		]);
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

		res.json({ ok: true, user: generateUserObject(user, req.usersIndex) });
		sendEventMessage([
			"<b>#USER_LINK_REMOVED</b>",
			eventFmt`user: ${{ type: "user", id: user.id, username: user.username }}`,
			`idx: ${linkIndex + 1}`
		]);
	}
);
