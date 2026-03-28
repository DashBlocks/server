import JSZip from "jszip";
import path from "path";
import { Readable } from "stream";

import app, { upload } from "../app.js";
import * as vars from "./vars.js";
import { validateId, isTrustedUrl, securityCheck, verifyAuth, uploadLimiter } from "./helpers.js";
import { uploadToTelegram, fetchFromTelegram, updateUsersIndex } from "./telegram.js";

app.post(
	"/save-project",
	verifyAuth,
	securityCheck,
	uploadLimiter,
	upload.single("file"),
	async (req, res) => {
		// Save project
		const { name, description } = req.body;
		const metadata = JSON.stringify({
			name: name || "Untitled",
			description: description || "",
			author: { id: Number(req.user.userId), username: req.user.username }
		});

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

		// Sending to getters group cuz we need to check if file and caption
		// uploaded successfully, and if not, we don't want to waste ID
		let projectId = await uploadToTelegram(
			vars.GETTERS_GROUP_ID,
			file.buffer,
			`${name || "Untitled"}.dbp.zip`,
			metadata
		);
		if (projectId) {
			const forwardRes = await fetch(`${vars.TELEGRAM_API}/forwardMessage`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					chat_id: vars.GETTERS_GROUP_ID,
					from_chat_id: vars.GETTERS_GROUP_ID,
					message_id: projectId
				})
			});

			const data = await forwardRes.json();
			if (!data.result.document.file_id)
				return res
					.status(500)
					.json({ ok: false, error: "Failed to upload project" });
			try {
				JSON.parse(data.result.caption);
			} catch (_) {
				return res
					.status(500)
					.json({ ok: false, error: "Failed to upload project metadata" });
			}
		} else {
			return res
				.status(500)
				.json({ ok: false, error: "Failed to upload project" });
		}
		projectId = await uploadToTelegram(
			vars.PROJECTS_GROUP_ID,
			file.buffer,
			`${name || "Untitled"}.dbp.zip`,
			metadata
		);

		// Update user profile
		const index = req.usersIndex;
		const userKey = req.user.username.toLowerCase();
		const user = index.users[userKey];

		user.projects.push({
			id: projectId,
			name: name || "Untitled",
			description: description || "",
			stats: {
				fires: 0
			}
		});

		const accountAgeMs = Date.now() - new Date(user.joinedAt).getTime();

		const hasEnoughProjects = user.projects.length >= 3;
		const isOldEnough = accountAgeMs >= 14 * 24 * 60 * 60 * 1000;
		const isActive =
			new Date(user.lastActive).getTime() >
			Date.now() - 7 * 24 * 60 * 60 * 1000;

		user.lastActive = new Date().toISOString();

		if (
			user.role === "dasher" &&
			hasEnoughProjects &&
			isOldEnough &&
			isActive
		) {
			user.role = "dasher+";
		}

		await updateUsersIndex(index);

		res.json({ ok: true, projectId });
	}
);

app.get("/get-project/:id", validateId, securityCheck, async (req, res) => {
	try {
		const downloadUrl = await fetchFromTelegram(
			req.params.id,
			vars.PROJECTS_GROUP_ID
		);
		const fileRes = await fetch(downloadUrl);
		res.setHeader("Content-Type", "application/zip");
		res.setHeader(
			"Content-Disposition",
			`attachment; filename="${req.params.id}.dbp.zip"`
		);
		Readable.fromWeb(fileRes.body).pipe(res);
	} catch (_) {
		res.status(404).json({ ok: false, error: "Project not found" });
	}
});

app.get("/projects/:id", validateId, securityCheck, async (req, res) => {
	try {
		const forwardRes = await fetch(`${vars.TELEGRAM_API}/forwardMessage`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				chat_id: vars.GETTERS_GROUP_ID,
				from_chat_id: vars.PROJECTS_GROUP_ID,
				message_id: req.params.id
			})
		});

		const data = await forwardRes.json();
		if (!data.ok || !data.result.document)
			return res.status(404).json({ ok: false, error: "Project not found" });

		const doc = data.result.document;
		const projectId = data.result.forward_from_message_id;
		const metadata = {
			name: "Untitled",
			description: "",
			thumbnailId: 1,
			stats: {
				fires: 0
			},
			author: {
				id: null,
				username: "Unknown",
				role: "dasher",
				profile: { avatarId: 1, description: "" },
				joinedAt: null,
				lastActive: null,
				projects: []
			}
		};

		try {
			const savedData = JSON.parse(data.result.caption);
			metadata.name = savedData.name || "Untitled";
			metadata.description = savedData.description || "";
			if (savedData.author) {
				metadata.author.id = Number(savedData.author.id) || null;
				metadata.author.username = savedData.author.username || "Unknown";
			}

			const authorProfile =
				req.usersIndex.users[metadata.author.username.toLowerCase()];
			if (authorProfile) {
				metadata.author.role = authorProfile.role || "dasher";
				metadata.author.joinedAt = authorProfile.joinedAt || null;
				metadata.author.lastActive = authorProfile.lastActive || null;
				metadata.author.projects = authorProfile.projects || [];
				const projectInIndex = metadata.author.projects.find(
					(p) => String(p.id) === String(req.params.id)
				);
				if (projectInIndex) {
					metadata.stats.fires = projectInIndex.stats?.fires || 0;
					metadata.thumbnailId = projectInIndex.thumbnailId || 1;
				}
				metadata.author.profile = {
					description: authorProfile.description || "",
					avatarId: authorProfile.avatarId || 1
				};
			}
		} catch (_) {
			// It might be old project
			const lastUnderscoreIndex = doc.file_name.lastIndexOf("_");
			if (lastUnderscoreIndex !== -1) {
				metadata.name = doc.file_name.substring(0, lastUnderscoreIndex);
				metadata.author.username = doc.file_name
					.substring(lastUnderscoreIndex + 1)
					.replace(".dbp.zip", "");
			} else if (doc.file_name.endsWith(".dbp.zip")) {
				metadata.name =
					doc.file_name.replace(".dbp.zip", "") !== ""
						? doc.file_name.replace(".dbp.zip", "")
						: "Untitled";
			}
		}

		res.json({
			ok: true,
			project: {
				id: projectId,
				name: metadata.name,
				description: metadata.description,
				thumbnailId: metadata.thumbnailId,
				stats: {
					fires: metadata.stats.fires
					// TODO: Views, remixes, etc
				},
				author: metadata.author,
				fileSize: doc.file_size,
				uploadedAt: data.result.forward_date
					? new Date(data.result.forward_date * 1000).toISOString()
					: null
			}
		});
	} catch (_) {
		res
			.status(500)
			.json({ ok: false, error: "Failed to fetch project metadata" });
	}
});

app.delete(
	"/projects/:id",
	verifyAuth,
	validateId,
	securityCheck,
	async (req, res) => {
		const projectId = req.params.id;
		const index = req.usersIndex;
		const userKey =
			req.userRole === "dashteam" && req.body?.targetUsername
				? req.body.targetUsername.toLowerCase()
				: req.user.username.toLowerCase();

		const userProfile = index.users[userKey];
		if (!userProfile)
			return res.status(404).json({ ok: false, error: "User not found" });

		const project = userProfile.projects.find(
			(p) => String(p.id) === String(projectId)
		);
		if (!project)
			return res
				.status(404)
				.json({ ok: false, error: "Project not found in profile" });

		const delRes = await fetch(`${vars.TELEGRAM_API}/deleteMessage`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				chat_id: vars.PROJECTS_GROUP_ID,
				message_id: projectId
			})
		});
		const delData = await delRes.json();
		if (!delData)
			return res.status(404).json({ ok: false, error: "Project not found" });

		// Don't even try to delete thumbnail cuz it may be a placeholder or just not exist
		if (project.thumbnailId > 1) {
			await fetch(`${vars.TELEGRAM_API}/deleteMessage`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					chat_id: vars.THUMBNAILS_GROUP_ID,
					message_id: project.thumbnailId
				})
			});
			// Ignore if failed
		}

		userProfile.projects = userProfile.projects.filter(
			(p) => String(p.id) !== String(projectId)
		);
		await updateUsersIndex(index);

		res.json({ ok: true, projects: userProfile.projects });
	}
);

app.post(
	"/projects/:id/upload-thumbnail",
	verifyAuth,
	securityCheck,
	upload.single("thumbnail"),
	async (req, res) => {
		const projectId = req.params.id;
		if (!req.file)
			return res.status(400).json({ ok: false, error: "No image provided" });

		const index = req.usersIndex;
		const userKey = req.user.username.toLowerCase();
		const userProjects = index.users[userKey].projects;

		const project = userProjects.find(
			(p) => String(p.id) === String(projectId)
		);
		if (!project)
			return res
				.status(404)
				.json({ ok: false, error: "Project not found in your profile" });

		// Don't even try to delete previous thumbnail cuz it may be a placeholder or just not exist
		if (project.thumbnailId > 1) {
			await fetch(`${vars.TELEGRAM_API}/deleteMessage`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					chat_id: vars.THUMBNAILS_GROUP_ID,
					message_id: project.thumbnailId
				})
			});
			// Ignore if failed
		}

		const thumbnailId = await uploadToTelegram(
			vars.THUMBNAILS_GROUP_ID,
			req.file.buffer,
			`thumb_${projectId}.png`
		);

		if (!thumbnailId)
			return res.status(500).json({ ok: false, error: "Upload failed" });

		project.thumbnailId = thumbnailId;
		await updateUsersIndex(index);
		res.json({ ok: true, thumbnailId });
	}
);

app.get("/projects/thumbnails/:id", async (req, res) => {
	try {
		const downloadUrl = await fetchFromTelegram(
			req.params.id,
			vars.THUMBNAILS_GROUP_ID
		);
		const fileRes = await fetch(downloadUrl);

		res.setHeader("Content-Type", "image/png");
		Readable.fromWeb(fileRes.body).pipe(res);
	} catch (_) {
		res.setHeader("Content-Type", "image/png");
		res.sendFile(path.join(vars.ASSETS_PATH, "dasher-icon.png"));
	}
});
