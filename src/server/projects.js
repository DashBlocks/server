import jwt from "jsonwebtoken";
import path from "path";

import app, { upload, imageUpload } from "../app.js";
import * as vars from "./vars.js";
import {
	validateId,
	validateProjectZip,
	securityCheck,
	verifyAuth,
	uploadLimiter,
	projectUploadTimeout,
	thumbnailUploadTimeout,
	escapeHTML,
	sendEventMessage
} from "./helpers.js";
import { formatThumbnailImage } from "./image-processing.js";
import * as storage from "./storage.js";

const views = new Map();
setInterval(() => {
	const oneHourAgo = Date.now() - (60 * 60 * 1000);
	for (const [key, timestamp] of views.entries()) {
		if (timestamp < oneHourAgo) {
			views.delete(key);
		}
	}
}, 15 * 60 * 1000);

app.post(
	"/save-project",
	verifyAuth,
	securityCheck,
	uploadLimiter,
	projectUploadTimeout,
	upload.single("file"),
	async (req, res) => {
		// Save project
		const { name, description, parentId } = req.body;
		if (typeof name !== "string")
			return res.status(400).json({ ok: false, error: "Name is required" });
		if (name.length < 1 || name.length > 100)
			return res.status(400).json({ ok: false, error: "Project name is too short or too long (minimum length 1, maximum length 100)" });
		if (description?.length > 1000)
			return res.status(400).json({ ok: false, error: "Project description is too long (maximum length 1000)" });

		const file = req.file;
		if (!file)
			return res.status(400).json({ ok: false, error: "No file uploaded" });

		const validation = await validateProjectZip(file, req.userRole);
		if (!validation.ok)
			return res.status(400).json({ ok: false, error: validation.error });

		const index = req.usersIndex;
		let parentProject = null;
		if (parentId !== undefined && parentId !== null && parentId !== "") {
			parentProject = storage.findProjectById(index, parentId);
			if (!parentProject)
				return res.status(404).json({ ok: false, error: "Parent project not found" });
		}

		const projectId = index.nextProjectId;
        
		try {
			await storage.saveProjectFile(projectId, file.buffer);
		} catch (_) {
			return res.status(500).json({ ok: false, error: "Failed to save project file" });
		}

		const userKey = req.user.username.toLowerCase();
		const user = index.users[userKey];

		user.projects.push({
			id: projectId,
			name: name || "Untitled",
			description: description || "",
			parentId: parentProject?.id || null,
			thumbnailId: 1,
			stats: {
				views: 0,
				fires: 0,
				forks: 0
			},
			forks: [],
			uploadedAt: new Date().toISOString(),
			updatedAt: new Date().toISOString()
		});

		index.nextProjectId++;

		if (parentProject) {
			parentProject.stats = {
				views: parentProject.stats?.views || 0,
				fires: parentProject.stats?.fires || 0,
				forks: (parentProject.stats?.forks || 0) + 1
			};
			parentProject.forks = parentProject.forks || [];
			parentProject.forks.push({
				id: projectId,
				name: name || "Untitled",
				parentId: parentProject.id,
				uploadedAt: user.projects.at(-1).uploadedAt
			});
		}

		if (!user.achievements) user.achievements = [];
		if ([1, 25, 50, 100, 250, 500, 1000, 5000, 10000].includes(user.projects.length))
			user.achievements.push({
				type: "reached-projects-count",
				project: {
					id: projectId,
					name: name || "Untitled"
				},
				count: user.projects.length,
				date: new Date().toISOString()
			});

		const accountAgeMs = Date.now() - new Date(user.joinedAt).getTime();
		const hasEnoughProjects = user.projects.length >= 3;
		const isOldEnough = accountAgeMs >= 14 * 24 * 60 * 60 * 1000;
		const isActive =
			new Date(user.lastActive).getTime() >
			Date.now() - 7 * 24 * 60 * 60 * 1000;

		user.lastActive = new Date().toISOString();
		user.actions = user.actions || [];
		user.actions = [
			{
				type: "shared-project",
				project: {
					id: projectId,
					name: name || "Untitled"
				},
				date: new Date().toISOString()
			},
			...user.actions
		];

		if (
			user.role === "dasher" &&
			hasEnoughProjects &&
			isOldEnough &&
			isActive
		) {
			user.role = "dasher+";
			user.messages = [
				{
					type: "promoted",
					role: "dasher+",
					date: new Date().toISOString()
				},
				...(user.messages || [])
			];
			user.unreadMessages = (user.unreadMessages || 0) + 1;
		}

		await storage.updateIndex(index);

		res.json({ ok: true, projectId });
		sendEventMessage([
			"<b>#PROJECT_CREATED</b>",
			`project: <b>${escapeHTML(name)}</b> (id ${projectId})`,
			`author: <b>${user.username}</b> (id ${user.id})`
		]);
	}
);

app.get("/get-project/:id", securityCheck, validateId, async (req, res) => {
	try {
		const exists = await storage.projectFileExists(req.params.id);
		if (!exists) {
			return res.status(404).json({ ok: false, error: "Project not found" });
		}
        
		const fileStream = storage.streamProjectFile(req.params.id);
		res.setHeader("Content-Type", "application/zip");
		res.setHeader("Content-Disposition", `attachment; filename="${req.params.id}.dbp.zip"`);
		fileStream.pipe(res);
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to stream project" });
	}
});

app.get("/projects/:id", securityCheck, validateId, async (req, res) => {
	try {
		const projectInIndex = storage.findProjectById(req.usersIndex, req.params.id);
		if (!projectInIndex) return res.status(404).json({ ok: false, error: "Project not found" });

		const authorProfile = Object.values(req.usersIndex.users).find((u) =>
			u.projects?.some((p) => String(p.id) === String(req.params.id))
		);

		let fileSize = 0;
		try {
			const stats = await storage.getProjectStats(req.params.id);
			fileSize = stats.size;
		} catch (_) {/* ignore */}

		res.json({
			ok: true,
			project: {
				id: Number(req.params.id),
				name: projectInIndex.name || "Untitled",
				description: projectInIndex.description || "",
				thumbnailId: Number(req.params.id) || 1,
				stats: {
					views: projectInIndex.stats?.views || 0,
					fires: projectInIndex.stats?.fires || 0,
					forks: projectInIndex.stats?.forks || 0
				},
				author: {
					id: authorProfile?.id || null,
					username: authorProfile?.username || "Unknown",
					role: authorProfile?.role || "dasher",
					profile: { avatarId: authorProfile?.id || 1 },
					joinedAt: authorProfile?.joinedAt || null,
					lastActive: authorProfile?.lastActive || null
				},
				fileSize: fileSize,
				uploadedAt: projectInIndex.uploadedAt || null,
				updatedAt: projectInIndex.updatedAt || null,
				parentId: projectInIndex.parentId || null
			}
		});
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to fetch project metadata" });
	}
});

app.get("/projects/:id/forks", securityCheck, validateId, (req, res) => {
	const project = storage.findProjectById(req.usersIndex, req.params.id);
	if (!project)
		return res.status(404).json({ ok: false, error: "Project not found" });

	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = isNaN(offset) ? 0 : Math.max(0, offset);

	const forks = (project.forks || []).slice(offset, offset + limit).flatMap((fork) => {
		const forkProject = storage.findProjectById(req.usersIndex, fork.id);
		if (!forkProject) return [];

		return [{
			id: forkProject.id || null,
			name: forkProject.name || "Unknown",
			description: forkProject.description || "",
			stats: {
				views: forkProject.stats?.views || 0,
				fires: forkProject.stats?.fires || 0,
				forks: forkProject.stats?.forks || 0
			},
			thumbnailId: forkProject.id || 1,
			uploadedAt: forkProject.uploadedAt || null
		}];
	});

	res.json({ ok: true, forks });
});

app.patch(
	"/projects/:id",
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		const projectId = req.params.id;
		const { name, description } = req.body;
 
		if (name === undefined && description === undefined)
			return res.status(400).json({ ok: false, error: "Nothing to update" });
 
		if (name !== undefined) {
			if (typeof name !== "string" || name.trim().length === 0)
				return res.status(400).json({ ok: false, error: "Project name cannot be empty" });
			if (name.length > 100)
				return res.status(400).json({ ok: false, error: "Project name is too long (maximum length 100)" });
		}
		if (description !== undefined) {
			if (typeof description !== "string")
				return res.status(400).json({ ok: false, error: "Invalid description" });
			if (description.length > 1000)
				return res.status(400).json({ ok: false, error: "Project description is too long (maximum length 1000)" });
		}
 
		const index = req.usersIndex;
		const isDashTeam = req.userRole === "dashteam";
 
		const authorKey = isDashTeam && req.body?.targetUsername
			? req.body.targetUsername.toLowerCase()
			: req.user.username.toLowerCase();
 
		const userProfile = index.users[req.user.username.toLowerCase()];
		let authorProfile = index.users[authorKey];
 
		if (isDashTeam && !req.body?.targetUsername) {
			authorProfile = Object.values(index.users).find((profile) =>
				profile.projects?.some((project) => String(project.id) === String(projectId))
			);
		}
 
		const project = authorProfile?.projects?.find(
			(p) => String(p.id) === String(projectId)
		);
 
		if (!isDashTeam && !project) {
			return res.status(403).json({ ok: false, error: "Project not found in your profile" });
		}
		if (!project) {
			return res.status(404).json({ ok: false, error: "Project not found" });
		}
 
		if (name !== undefined) project.name = name.trim();
		if (description !== undefined) project.description = description;
		project.updatedAt = new Date().toISOString();
		userProfile.lastActive = new Date().toISOString();
 
		await storage.updateIndex(index);
 
		res.json({
			ok: true,
			project: {
				id: projectId,
				name: project.name,
				description: project.description
			}
		});
		if (isDashTeam && userProfile.id !== authorProfile.id) {
			sendEventMessage([
				"<b>#ADMIN #PROJECT_METADATA_EDITED</b>",
				`admin: <b>${userProfile.username}</b> (id ${userProfile.id})`,
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		} else {
			sendEventMessage([
				"<b>#PROJECT_METADATA_EDITED</b>",
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		}
	}
);

app.put(
	"/projects/:id",
	verifyAuth,
	securityCheck,
	uploadLimiter,
	projectUploadTimeout,
	validateId,
	upload.single("file"),
	async (req, res) => {
		const projectId = req.params.id;
		const { name, description } = req.body;
		const file = req.file;
 
		if (name !== undefined) {
			if (typeof name !== "string" || name.trim().length === 0)
				return res.status(400).json({ ok: false, error: "Project name cannot be empty" });
			if (name.length > 100)
				return res.status(400).json({ ok: false, error: "Project name is too long (maximum length 100)" });
		}
		if (description !== undefined) {
			if (typeof description !== "string")
				return res.status(400).json({ ok: false, error: "Invalid description" });
			if (description.length > 1000)
				return res.status(400).json({ ok: false, error: "Project description is too long (maximum length 1000)" });
		}
 
		const validation = await validateProjectZip(file, req.userRole);
		if (!validation.ok)
			return res.status(400).json({ ok: false, error: validation.error });
 
		const index = req.usersIndex;
		const isDashTeam = req.userRole === "dashteam";
 
		const authorKey = isDashTeam && req.body?.targetUsername
			? req.body.targetUsername.toLowerCase()
			: req.user.username.toLowerCase();
 
		const userProfile = index.users[req.user.username.toLowerCase()];
		let authorProfile = index.users[authorKey];
 
		if (isDashTeam && !req.body?.targetUsername) {
			authorProfile = Object.values(index.users).find((profile) =>
				profile.projects?.some((project) => String(project.id) === String(projectId))
			);
		}
 
		const project = authorProfile?.projects?.find(
			(p) => String(p.id) === String(projectId)
		);
 
		if (!isDashTeam && !project) {
			return res.status(403).json({ ok: false, error: "Project not found in your profile" });
		}
		if (!project) {
			return res.status(404).json({ ok: false, error: "Project not found" });
		}
 
		try {
			await storage.saveProjectFile(projectId, file.buffer);
		} catch (_) {
			return res.status(500).json({ ok: false, error: "Failed to save project file" });
		}
 
		if (name !== undefined) project.name = name.trim();
		if (description !== undefined) project.description = description;
		project.updatedAt = new Date().toISOString();
		userProfile.lastActive = new Date().toISOString();
 
		await storage.updateIndex(index);
 
		res.json({ ok: true });
		if (isDashTeam && userProfile.id !== authorProfile.id) {
			sendEventMessage([
				"<b>#ADMIN #PROJECT_EDITED</b>",
				`admin: <b>${userProfile.username}</b> (id ${userProfile.id})`,
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		} else {
			sendEventMessage([
				"<b>#PROJECT_EDITED</b>",
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		}
	}
);

app.delete(
	"/projects/:id",
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		const projectId = req.params.id;
		const index = req.usersIndex;
		const isDashTeam = req.userRole === "dashteam";

		const authorKey = isDashTeam && req.body?.targetUsername
			? req.body.targetUsername.toLowerCase()
			: req.user.username.toLowerCase();
 
		const userProfile = index.users[req.user.username.toLowerCase()];
		let authorProfile = index.users[authorKey];

		if (isDashTeam && !req.body?.targetUsername) {
			authorProfile = Object.values(index.users).find((profile) =>
				profile.projects?.some((project) => String(project.id) === String(projectId))
			);
		}

		if (!isDashTeam) {
			if (!authorProfile?.projects?.some((p) => String(p.id) === String(projectId))) {
				return res.status(403).json({ ok: false, error: "Project not found in your profile" });
			}
		}

		const project = authorProfile?.projects?.find(
			(p) => String(p.id) === String(projectId)
		) || null;
		const parentProject = project?.parentId
			? storage.findProjectById(index, project.parentId)
			: null;

		try {
			await storage.deleteProjectFile(projectId);
			if ((project?.thumbnailId || 0) > 1) {
				await storage.deleteThumbnailFile(project.thumbnailId);
			}
		} catch (_) {
			return res.status(500).json({ ok: false, error: "Failed to delete project files" });
		}

		if (authorProfile) {
			authorProfile.projects = (authorProfile.projects || []).filter(
				(p) => String(p.id) !== String(projectId)
			);
			if (parentProject) {
				parentProject.stats = {
					views: parentProject.stats?.views || 0,
					fires: parentProject.stats?.fires || 0,
					forks: Math.max(0, (parentProject.stats?.forks || 0) - 1)
				};
				parentProject.forks = (parentProject.forks || []).filter(
					(fork) => String(fork.id) !== String(projectId)
				);
			}
			if (String(authorProfile.recommendedProject?.id) === String(projectId))
				authorProfile.recommendedProject = {
					id: null,
					name: "Unknown",
					thumbnailId: 1
				};
			if (index.featuredProjects?.find((p) => String(p.id) === String(projectId)))
				index.featuredProjects = index.featuredProjects.filter(
					(p) => String(p.id) !== String(projectId)
				);
			userProfile.lastActive = new Date().toISOString();
			await storage.updateIndex(index);
		}

		res.json({ ok: true, projects: authorProfile?.projects || [] });
		if (isDashTeam && userProfile.id !== authorProfile.id) {
			sendEventMessage([
				"<b>#ADMIN #PROJECT_DELETED</b>",
				`admin: <b>${userProfile.username}</b> (id ${userProfile.id})`,
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		} else {
			sendEventMessage([
				"<b>#PROJECT_DELETED</b>",
				`project: <b>${escapeHTML(project.name)}</b> (id ${projectId})`,
				`author: <b>${authorProfile.username}</b> (id ${authorProfile.id})`
			]);
		}
	}
);

app.post(
	"/projects/:id/upload-thumbnail",
	verifyAuth,
	securityCheck,
	validateId,
	uploadLimiter,
	thumbnailUploadTimeout,
	imageUpload.single("thumbnail"),
	async (req, res) => {
		const projectId = req.params.id;
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		const index = req.usersIndex;
		const userKey = req.user.username.toLowerCase();
		const isDashTeam = req.userRole === "dashteam";
		let user = index.users[userKey];

		if (isDashTeam) {
			user = Object.values(index.users).find((profile) =>
				profile.projects?.some((project) => String(project.id) === String(projectId))
			);
			if (!user)
				return res.status(404).json({ ok: false, error: "Project not found" });
		}
		if (!user?.projects?.find((p) => String(p.id) === String(projectId)) && !isDashTeam)
			return res
				.status(404)
				.json({ ok: false, error: "Project not found in your profile" });

		const userProjects = user?.projects;
		const project = userProjects?.find(
			(p) => String(p.id) === String(projectId)
		) || null;
		if (!project)
			return res.status(404).json({ ok: false, error: "Project not found" });

		if (project.thumbnailId > 1) {
			try {
				await storage.deleteThumbnailFile(project.thumbnailId);
			} catch (_) {
				return res.status(500).json({ ok: false, error: "Failed to delete prev thumbnail" });
			}
		}

		const thumbnailId = project.id;

		try {
			const formatted = await formatThumbnailImage(req.file.buffer);
			await storage.saveThumbnailFile(thumbnailId, formatted);
		} catch (error) {
			if (error?.message === "Invalid image file" || error?.message === "Format not supported") {
				return res.status(400).json({ ok: false, error: error.message });
			}
			return res.status(500).json({ ok: false, error: "Upload failed" });
		}

		project.thumbnailId = thumbnailId;
		user.lastActive = new Date().toISOString();
		await storage.updateIndex(index);

		res.json({ ok: true, thumbnailId });
	}
);

app.get("/projects/thumbnails/:id", validateId, async (req, res) => {
	try {
		const exists = await storage.thumbnailFileExists(req.params.id);
		if (!exists) throw new Error("Not found");
        
		const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(req.params.id));
		res.setHeader("Content-Type", "image/png");
		res.sendFile(path.join(projectDir, `${req.params.id}.png`));
	} catch (_) {
		res.setHeader("Content-Type", "image/png");
		res.sendFile(path.join(vars.ASSETS_PATH, "dasher-icon.png"));
	}
});

app.post("/projects/:id/view", async (req, res) => {
	const projectId = req.params.id;
	let viewerId;
	const token = req.cookies?.auth_token;
    
	if (token) {
		try {
			const decoded = jwt.verify(token, vars.JWT_SECRET);
			viewerId = `user_${decoded.userId}`;
		} catch (_) {
			viewerId = `ip_${req.headers["x-forwarded-for"] || req.socket.remoteAddress}`;
		}
	} else {
		viewerId = `ip_${req.headers["x-forwarded-for"] || req.socket.remoteAddress}`;
	}

	const key = `${projectId}_${viewerId}`;

	try {
		const index = await storage.getIndex();
		const authorProfile = Object.values(index.users).find((u) =>
			u.projects?.some((p) => String(p.id) === String(projectId))
		);
		let project;
		if (authorProfile) {
			project = authorProfile.projects.find((p) => String(p.id) === String(projectId));
			project.stats = project.stats || {};
			if (views.has(key)) {
        		return res.json({ ok: true, message: "View already counted recently", views: project.stats.views || 0 });
    		}
    		views.set(key, Date.now());
			project.stats.views = (project.stats.views || 0) + 1;
			await storage.updateIndex(index);
		}
		res.json({ ok: true, views: project?.stats.views || 0 });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to count view", views: 0 });
	}
});

app.post(
	"/projects/:id/fire",
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		const projectId = req.params.id;
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		if (user.firedProjects?.includes(Number(projectId)) || user.firedProjects?.includes(String(projectId)))
			return res.status(400).json({ ok: false, error: "Project already fired" });

		const projectInIndex = storage.findProjectById(index, projectId);
		if (!projectInIndex) return res.status(404).json({ ok: false, error: "Project not found" });

		const authorProfile = Object.values(index.users).find((u) =>
			u.projects?.some((p) => String(p.id) === String(projectId))
		);

		if (!authorProfile) return res.status(404).json({ ok: false, error: "Author profile not found" });

		const project = authorProfile.projects.find((p) => String(p.id) === String(projectId));
        
		project.stats ? project.stats.fires += 1 : project.stats = { fires: 1 };
		user.firedProjects ? user.firedProjects.push(Number(projectId)) : user.firedProjects = [Number(projectId)];
        
		if (user.id !== authorProfile.id) {
			authorProfile.messages = [
				{
					type: "fired",
					id: Number(projectId),
					name: project.name,
					user: {
						id: user.id,
						username: user.username
					},
					date: new Date().toISOString()
				},
				...(authorProfile.messages || [])
			];
			authorProfile.unreadMessages = (authorProfile.unreadMessages || 0) + 1;
		}

		user.lastActive = new Date().toISOString();
		user.actions = user.actions || [];
		user.actions = [
			{
				type: "fired-project",
				project: {
					id: Number(projectId),
					name: project.name
				},
				date: new Date().toISOString()
			},
			...user.actions
		];
        
		await storage.updateIndex(index);
		res.json({ ok: true, fires: project.stats.fires });
	}
);

app.delete(
	"/projects/:id/fire",
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		const projectId = req.params.id;
		const index = req.usersIndex;
		const user = index.users[req.user.username.toLowerCase()];
        
		const isFired = user.firedProjects?.includes(Number(projectId)) || user.firedProjects?.includes(String(projectId));
		if (!isFired)
			return res.status(400).json({ ok: false, error: "Project is not fired" });

		const authorProfile = Object.values(index.users).find((u) =>
			u.projects?.some((p) => String(p.id) === String(projectId))
		);
		if (!authorProfile) return res.status(404).json({ ok: false, error: "Project author not found" });

		const project = authorProfile.projects.find((p) => String(p.id) === String(projectId));

		project.stats && project.stats.fires > 0 ? project.stats.fires -= 1 : project.stats = { fires: 0 };
		user.firedProjects = user.firedProjects ? user.firedProjects.filter((id) => String(id) !== String(projectId)) : [];
        
		authorProfile.messages = authorProfile.messages?.filter(
			(m) => !(m.type === "fired" && String(m.id) === String(projectId) && m.user?.id === user.id)
		) || [];
		authorProfile.unreadMessages = (authorProfile.unreadMessages || 1) - 1;
        
		user.lastActive = new Date().toISOString();
		await storage.updateIndex(index);
		res.json({ ok: true, fires: project.stats.fires });
	}
);
