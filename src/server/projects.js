import JSZip from "jszip";
import path from "path";

import app, { upload } from "../app.js";
import * as vars from "./vars.js";
import { validateId, isTrustedUrl, securityCheck, verifyAuth, uploadLimiter, uploadTimeout, sendEventMessage } from "./helpers.js";
import * as storage from "./storage.js";

app.post(
	"/save-project",
	verifyAuth,
	securityCheck,
	uploadLimiter,
	uploadTimeout,
	upload.single("file"),
	async (req, res) => {
		// Save project
		const { name, description } = req.body;
		if (typeof name !== "string" || typeof description !== "string")
			return res.status(400).json({ ok: false, error: "Name and description are required" });
		if (name.length > 100)
			return res.status(400).json({ ok: false, error: "Project name is too long (maximum length 100)" });
		if (description.length > 1000)
			return res.status(400).json({ ok: false, error: "Project description is too long (maximum length 1000)" });

		const file = req.file;
		if (!file)
			return res.status(400).json({ ok: false, error: "No file uploaded" });

		const zip = await JSZip.loadAsync(file.buffer);
		const projectData = await zip.file("project.json")?.async("string");
		if (!projectData)
			return res
				.status(400)
				.json({ ok: false, error: "project.json not found" });
		const projectJson = JSON.parse(projectData);
		const hasCustomExtensions = Object.values(
			projectJson.extensionURLs || {}
		).some(
			(ext) =>
				(ext.startsWith("http") || ext.startsWith("data")) &&
                !isTrustedUrl(ext)
		);
		if (hasCustomExtensions && req.userRole === "dasher") {
			return res
				.status(403)
				.json({ ok: false, error: "Custom extensions require Dasher+ role" });
		}

		const maxProjectSize = req.userRole === "dash-supporter" ? 200 * 1024 * 1024 : 50 * 1024 * 1024;
		if (file.size > maxProjectSize) {
			return res.status(400).json({ ok: false, error: `Project size limit is ${req.userRole === "dash-supporter" ? "200MB" : "50MB"}` });
		}

		const index = req.usersIndex;

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
			thumbnailId: 1,
			stats: {
				fires: 0
			},
			uploadedAt: new Date().toISOString()
		});

		index.nextProjectId++;

		if (!user.achievements) user.achievements = [];
		if (user.projects.length === 1)
			user.achievements.push({
				type: "first-project",
				project: {
					id: projectId,
					name: name || "Untitled"
				},
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
		}

		await storage.updateIndex(index);

		res.json({ ok: true, projectId });
		sendEventMessage(`Project created: <b>${name}</b> (id ${projectId}) by <b>${user.username}</b> (id ${user.id})`);
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
					fires: projectInIndex.stats?.fires || 0
					// TODO: Views, remixes, etc
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
				uploadedAt: projectInIndex.uploadedAt || null
			}
		});
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to fetch project metadata" });
	}
});

app.delete(
	"/projects/:id",
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		const projectId = req.params.id;
		const index = req.usersIndex;
		const isDashTeam = req.userRole === "dashteam";

		const userKey = isDashTeam && req.body?.targetUsername
			? req.body.targetUsername.toLowerCase()
			: req.user.username.toLowerCase();

		let userProfile = index.users[userKey];

		if (isDashTeam && !req.body?.targetUsername) {
			userProfile = Object.values(index.users).find((profile) =>
				profile.projects?.some((project) => String(project.id) === String(projectId))
			);
		}

		if (!isDashTeam) {
			if (!userProfile?.projects?.some((p) => String(p.id) === String(projectId))) {
				return res.status(403).json({ ok: false, error: "Project not found in your profile" });
			}
		}

		const project = userProfile?.projects?.find(
			(p) => String(p.id) === String(projectId)
		) || null;

		try {
			await storage.deleteProjectFile(projectId);
			if ((project?.thumbnailId || 0) > 1) {
				await storage.deleteThumbnailFile(project.thumbnailId);
			}
		} catch (_) {
			return res.status(500).json({ ok: false, error: "Failed to delete project files" });
		}

		if (userProfile) {
			userProfile.projects = (userProfile.projects || []).filter(
				(p) => String(p.id) !== String(projectId)
			);
			userProfile.lastActive = new Date().toISOString();
			if (String(userProfile.recommendedProject?.id) === String(projectId))
				userProfile.recommendedProject = {
					id: null,
					name: "Unknown",
					thumbnailId: 1
				};
			await storage.updateIndex(index);
		}

		return res.json({ ok: true, projects: userProfile?.projects || [] });
	}
);

app.post(
	"/projects/:id/upload-thumbnail",
	verifyAuth,
	securityCheck,
	validateId,
	upload.single("thumbnail"),
	async (req, res) => {
		const projectId = req.params.id;
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		const index = req.usersIndex;
		const userKey = req.user.username.toLowerCase();
		const user = index.users[userKey];
		const userProjects = user?.projects;

		const project = userProjects?.find(
			(p) => String(p.id) === String(projectId)
		);
		if (!project)
			return res
				.status(404)
				.json({ ok: false, error: "Project not found in your profile" });

		if (project.thumbnailId > 1) {
			await storage.deleteThumbnailFile(project.thumbnailId);
		}

		const thumbnailId = project.id;

		try {
			await storage.saveThumbnailFile(thumbnailId, req.file.buffer);
		} catch (_) {
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
        
		user.lastActive = new Date().toISOString();
		await storage.updateIndex(index);
		res.json({ ok: true, fires: project.stats.fires });
	}
);
