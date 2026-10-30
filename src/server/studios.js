import path from "path";

import app, { imageUpload } from "../app.js";
import * as vars from "./vars.js";
import {
	validateId,
	getProjectStudiosCount,
	generateUserObject,
	securityCheck,
	verifyAuth,
	uploadLimiter,
	studioCreationLimiter,
	studioCreationTimeout,
	studioProjectAdditionLimiter,
	studioProjectAdditionTimeout,
	thumbnailUploadTimeout,
	sendEventMessage,
	eventFmt
} from "./util/helpers.js";
import { formatStudioThumbnailImage } from "./util/image-processing.js";
import * as storage from "./storage.js";

const getStudio = (index, studioId) => index.studios?.[String(studioId)] || null;

const isStudioOwner = (studio, user) => String(studio.ownerId) === String(user.id);

const findProjectOwner = (index, projectId) => {
	for (const user of Object.values(index.users || {})) {
		const project = (user.projects || []).find(
			(entry) => String(entry.id) === String(projectId)
		);
		if (project) return { user, project };
	}
	return null;
};

const formatStudio = (index, studio) => ({
	id: studio.id,
	owner: generateUserObject(
		index.users[studio.ownerUsername?.toLowerCase()],
		index
	),
	name: studio.name || "Untitled Studio",
	description: studio.description || "",
	allowProjects: !!studio.allowProjects,
	projectsCount: (studio.projects || []).length,
	thumbnailId: studio.id || 1,
	createdAt: studio.createdAt || null,
	updatedAt: studio.updatedAt || null
});

const formatStudioProject = (index, projectId) => {
	const owner = findProjectOwner(index, projectId);
	if (!owner) return null;
	const { user, project } = owner;
	return {
		id: project.id,
		name: project.name || "Untitled",
		description: project.description || "",
		thumbnailId: project.id || 1,
		stats: {
			views: project.stats?.views || 0,
			fires: project.stats?.fires || 0,
			forks: project.stats?.forks || 0,
			studios: getProjectStudiosCount(index, project.id)
		},
		author: {
			id: user.id,
			username: user.username || "Unknown"
		},
		uploadedAt: project.uploadedAt || null
	};
};

app.post("/studios", verifyAuth, securityCheck, studioCreationLimiter, studioCreationTimeout, async (req, res) => {
	const user = req.usersIndex.users[req.user.username.toLowerCase()];
	if (!user)
		return res.status(404).json({ ok: false, error: "User account not found" });

	const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
	if (!name || name.length > 100)
		return res.status(400).json({ ok: false, error: "Studio name must be between 1 and 100 characters" });
	if (req.body?.description !== undefined && typeof req.body.description !== "string")
		return res.status(400).json({ ok: false, error: "Studio description must be a string" });
	if (req.body?.description?.length > 1000)
		return res.status(400).json({ ok: false, error: "Studio description is too long (maximum length 1000)" });

	const index = req.usersIndex;
	index.studios = index.studios || {};
	const currentStudioId = Number(index.nextStudioId);
	const existingMaxId = Object.keys(index.studios).reduce((maxId, id) => {
		const parsedId = Number(id);
		return Number.isSafeInteger(parsedId) && parsedId > maxId ? parsedId : maxId;
	}, 0);
	const studioId = Number.isSafeInteger(currentStudioId) && currentStudioId > existingMaxId
		? currentStudioId
		: existingMaxId + 1;
	if (!Number.isSafeInteger(studioId) || studioId < 1)
		return res.status(500).json({ ok: false, error: "Invalid studio ID" });

	const now = new Date().toISOString();
	const studio = {
		id: studioId,
		ownerId: user.id,
		ownerUsername: user.username,
		name,
		description: req.body.description || "",
		allowProjects: false,
		projects: [],
		thumbnailId: studioId,
		createdAt: now,
		updatedAt: now
	};

	try {
		await storage.createStudioDirectory(studioId);
		index.studios[String(studioId)] = studio;
		index.nextStudioId++;
		user.lastActive = now;
		await storage.updateIndex(index);
	} catch (_) {
		return res.status(500).json({ ok: false, error: "Failed to create studio" });
	}

	res.json({
		ok: true,
		studio: {
			id: studio.id,
			owner: {
				...generateUserObject(req.usersIndex.users[studio.ownerUsername.toLowerCase()], req.usersIndex)
			},
			name: studio.name || "Untitled Studio",
			description: studio.description || "",
			allowProjects: !!studio.allowProjects,
			projectsCount: (studio.projects || []).length,
			thumbnailId: studio.id || 1,
			createdAt: studio.createdAt || null,
			updatedAt: studio.updatedAt || null
		}
	});
	sendEventMessage([
		"<b>#STUDIO_CREATED</b>",
		eventFmt`studio: ${{ type: "studio", id: studio.id, name: studio.name || "Untitled Studio" }}`,
		eventFmt`owner: ${{ type: "user", id: studio.ownerId, username: studio.ownerUsername }}`
	]);
});

app.delete("/studios/:id", verifyAuth, securityCheck, validateId, async (req, res) => {
	const index = req.usersIndex;
	const studio = getStudio(index, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	const user = index.users[req.user.username.toLowerCase()];
	if (!isStudioOwner(studio, user))
		return res.status(403).json({ ok: false, error: "Only the studio owner can delete it" });

	await storage.deleteStudioDirectory(studio.id);
	delete index.studios[String(req.params.id)];
	user.lastActive = new Date().toISOString();
	await storage.updateIndex(index);

	res.json({ ok: true });
	sendEventMessage([
		"<b>#STUDIO_DELETED</b>",
		eventFmt`studio: ${{ type: "studio", id: studio.id, name: studio.name || "Untitled Studio" }}`,
		eventFmt`owner: ${{ type: "user", id: studio.ownerId, username: studio.ownerUsername }}`
	]);
});

app.get("/studios/:id", securityCheck, validateId, (req, res) => {
	const index = req.usersIndex;
	const studio = getStudio(index, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	res.json({ ok: true, studio: formatStudio(index, studio) });
});

app.get("/projects/:id/studios", securityCheck, validateId, (req, res) => {
	const index = req.usersIndex;
	if (!findProjectOwner(index, req.params.id))
		return res.status(404).json({ ok: false, error: "Project not found" });

	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = Number.isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = Number.isNaN(offset) ? 0 : Math.max(0, offset);
	const studios = Object.values(index.studios || {}).toReversed()
		.filter((studio) => (studio.projects || []).some(
			(projectId) => String(projectId) === req.params.id
		));
	const formattedStudios = studios
		.slice(offset, offset + limit)
		.map((studio) => formatStudio(index, studio));

	res.json({
		ok: true,
		total: studios.length,
		studios: formattedStudios
	});
});

app.patch("/studios/:id", verifyAuth, securityCheck, validateId, async (req, res) => {
	const index = req.usersIndex;
	const studio = getStudio(index, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	const user = index.users[req.user.username.toLowerCase()];
	if (!isStudioOwner(studio, user))
		return res.status(403).json({ ok: false, error: "Only the studio owner can update it" });

	const { name, description, allowProjects } = req.body || {};
	if (name === undefined && description === undefined && allowProjects === undefined)
		return res.status(400).json({ ok: false, error: "Nothing to update" });
	if (name !== undefined && (typeof name !== "string" || !name.trim() || name.trim().length > 100))
		return res.status(400).json({ ok: false, error: "Studio name must be between 1 and 100 characters" });
	if (description !== undefined && (typeof description !== "string" || description.length > 1000))
		return res.status(400).json({ ok: false, error: "Invalid studio description" });
	if (allowProjects !== undefined && typeof allowProjects !== "boolean")
		return res.status(400).json({ ok: false, error: "allowProjects must be a boolean" });

	if (name !== undefined) studio.name = name.trim();
	if (description !== undefined) studio.description = description;
	if (allowProjects !== undefined) studio.allowProjects = allowProjects;
	studio.updatedAt = new Date().toISOString();
	user.lastActive = studio.updatedAt;
	await storage.updateIndex(index);

	res.json({
		ok: true,
		studio: {
			id: studio.id,
			owner: {
				...generateUserObject(req.usersIndex.users[studio.ownerUsername.toLowerCase()], req.usersIndex)
			},
			name: studio.name || "Untitled Studio",
			description: studio.description || "",
			allowProjects: !!studio.allowProjects,
			projectsCount: (studio.projects || []).length,
			thumbnailId: studio.id || 1,
			createdAt: studio.createdAt || null,
			updatedAt: studio.updatedAt || null
		}
	});
	if (name !== undefined || description !== undefined) {
		sendEventMessage([
			"<b>#STUDIO_EDITED</b>",
			eventFmt`studio: ${{ type: "studio", id: studio.id, name: studio.name || "Untitled Studio" }}`,
			eventFmt`owner: ${{ type: "user", id: studio.ownerId, username: studio.ownerUsername }}`
		]);
	}
});

app.get("/studios/:id/projects", securityCheck, validateId, (req, res) => {
	const studio = getStudio(req.usersIndex, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	let limit = parseInt(req.query.limit, 40);
	let offset = parseInt(req.query.offset, 0);
	limit = Number.isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = Number.isNaN(offset) ? 0 : Math.max(0, offset);
	const projectIds = (studio.projects || []).toReversed();
	const projects = projectIds
		.slice(offset, offset + limit)
		.map((projectId) => formatStudioProject(req.usersIndex, projectId))
		.filter(Boolean);

	res.json({ ok: true, projects });
});

app.post("/studios/:id/projects", verifyAuth, securityCheck, studioProjectAdditionLimiter, studioProjectAdditionTimeout, validateId, async (req, res) => {
	const index = req.usersIndex;
	const studio = getStudio(index, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	const user = index.users[req.user.username.toLowerCase()];
	if (!user) return res.status(404).json({ ok: false, error: "User account not found" });
	const owner = isStudioOwner(studio, user);
	if (!owner && !studio.allowProjects)
		return res.status(403).json({ ok: false, error: "This studio is not accepting projects" });

	const projectId = req.body?.projectId;
	if (!Number.isSafeInteger(Number(projectId)) || Number(projectId) < 1)
		return res.status(400).json({ ok: false, error: "Invalid project ID" });

	const projectOwner = findProjectOwner(index, projectId);
	if (!projectOwner)
		return res.status(404).json({ ok: false, error: "Project not found" });

	studio.projects = studio.projects || [];
	if (studio.projects.some((id) => String(id) === String(projectId)))
		return res.status(409).json({ ok: false, error: "Project is already in this studio" });

	studio.projects.push(projectOwner.project.id);
	studio.updatedAt = new Date().toISOString();
	user.lastActive = studio.updatedAt;
	await storage.updateIndex(index);
	res.json({ ok: true });
});

app.delete("/studios/:id/projects/:projectId", verifyAuth, securityCheck, validateId, async (req, res) => {
	const index = req.usersIndex;
	const studio = getStudio(index, req.params.id);
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });
	const user = index.users[req.user.username.toLowerCase()];
	if (!/^\d+$/.test(req.params.projectId) || req.params.projectId.startsWith("0"))
		return res.status(400).json({ ok: false, error: "Invalid project ID" });
	if (!(studio.projects || []).some((projectId) => String(projectId) === req.params.projectId))
		return res.status(404).json({ ok: false, error: "Project not found in this studio" });

	const projectOwner = findProjectOwner(index, req.params.projectId);
	const isProjectOwner = String(projectOwner?.user.id) === String(user?.id);
	if (!isStudioOwner(studio, user) && !isProjectOwner)
		return res.status(403).json({ ok: false, error: "Only the studio owner or project owner can remove projects" });

	studio.projects = (studio.projects || []).filter(
		(projectId) => String(projectId) !== req.params.projectId
	);
	studio.updatedAt = new Date().toISOString();
	user.lastActive = studio.updatedAt;
	await storage.updateIndex(index);
	res.json({ ok: true });
});

app.post(
	"/studios/:id/upload-thumbnail",
	verifyAuth,
	securityCheck,
	validateId,
	uploadLimiter,
	thumbnailUploadTimeout,
	imageUpload.single("thumbnail"),
	async (req, res) => {
		const index = req.usersIndex;
		const studio = getStudio(index, req.params.id);
		if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });
		const user = index.users[req.user.username.toLowerCase()];
		if (!isStudioOwner(studio, user))
			return res.status(403).json({ ok: false, error: "Only the studio owner can update its thumbnail" });
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		try {
			const formatted = await formatStudioThumbnailImage(req.file.buffer);
			await storage.saveStudioThumbnailFile(studio.id, formatted);
		} catch (error) {
			if (["Invalid image file", "Unsupported image format", "Image dimensions too large"].includes(error?.message))
				return res.status(400).json({ ok: false, error: error.message });
			return res.status(500).json({ ok: false, error: "Upload failed" });
		}

		studio.updatedAt = new Date().toISOString();
		user.lastActive = studio.updatedAt;
		await storage.updateIndex(index);
		res.json({ ok: true, thumbnailId: studio.id });
		sendEventMessage([
			"<b>#STUDIO_THUMBNAIL_UPDATED</b>",
			eventFmt`studio: ${{ type: "studio", id: studio.id, name: studio.name || "Untitled Studio" }}`,
			eventFmt`owner: ${{ type: "user", id: studio.ownerId, username: studio.ownerUsername }}`,
			`thumbnail: <b>${studio.id}</b>`
		]);
	}
);

app.get("/studios/thumbnails/:id", securityCheck, validateId, async (req, res) => {
	const studioId = req.params.id;
	const studio = getStudio(req.usersIndex, studioId);
	if (!studio || !(await storage.studioThumbnailFileExists(studioId))) {
		res.setHeader("Content-Type", "image/png");
		return res.sendFile(path.join(vars.ASSETS_PATH, "dasher-icon.png"));
	}

	res.setHeader("Content-Type", "image/png");
	res.sendFile(path.join(vars.DATA_STUDIOS_PATH, String(studioId), `${studioId}.png`));
});
