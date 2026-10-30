import app from "../app.js";
import {
	validateId,
	getProjectStudiosCount,
	generateUserObject,
	securityCheck,
	verifyAuth,
	sendEventMessage,
	eventFmt
} from "./util/helpers.js";
import * as storage from "./storage.js";

function formatFeaturedProjects(index, featuredProjects = index.featuredProjects || []) {
	return featuredProjects.flatMap((featuredProject) => {
		const project = storage.findProjectById(index, featuredProject.id);
		if (!project) return [];

		const author = Object.values(index.users).find((user) =>
			user.projects?.some((entry) => String(entry.id) === String(project.id))
		);

		return [{
			id: project.id || null,
			name: project.name || "Unknown",
			author: {
				id: author?.id || null,
				username: author?.username || "Unknown",
				profile: {
					avatarId: author?.id || 1
				},
				joinedAt: author?.joinedAt || null
			},
			thumbnailId: project.id || 1,
			stats: {
				views: project.stats?.views || 0,
				fires: project.stats?.fires || 0,
				forks: project.stats?.forks || 0,
				studios: getProjectStudiosCount(index, project.id)
			},
			uploadedAt: project.uploadedAt || null,
			featuredAt: featuredProject.featuredAt || null
		}];
	});
}

function formatFeaturedStudios(index, featuredStudios = index.featuredStudios || []) {
	return featuredStudios.flatMap((featuredStudio) => {
		const studio = index.studios?.[String(featuredStudio.id)];
		if (!studio) return [];

		return [{
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
			updatedAt: studio.updatedAt || null,
			featuredAt: featuredStudio.featuredAt || null
		}];
	});
}

app.post(
	["/featured/projects/:id", "/featured-projects/:id"],
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		if (req.userRole !== "dashteam")
			return res.status(403).json({
				ok: false,
				error: "Only Dash Team can do this, what did you expect?"
			});

		const projectId = req.params.id;
		const index = req.usersIndex;

		if (index.featuredProjects?.find((p) => String(p.id) === String(projectId)))
			return res.status(400).json({ ok: false, error: "Project already featured" });

		if (!index.featuredProjects) index.featuredProjects = [];

		const projectReq = await fetch(
			`https://api.dashblocks.org/projects/${projectId}`
		);
		if (!projectReq.ok)
			return res.status(404).json({ ok: false, error: "Project not found" });
		const projectData = (await projectReq.json()).project;

		index.featuredProjects = [
			{
				id: projectId,
				...projectData,
				featuredAt: new Date().toISOString()
			},
			...index.featuredProjects
		];

		const authorUsername = projectData.author.username.toLowerCase();
		if (index.users[authorUsername]) {
			index.users[authorUsername].messages = [
				{
					type: "featured",
					id: projectId,
					name: projectData.name,
					date: new Date().toISOString()
				},
				...(index.users[authorUsername].messages || [])
			];
			index.users[authorUsername].unreadMessages = (index.users[authorUsername].unreadMessages || 0) + 1;
		}

		await storage.updateIndex(index);

		const projects = formatFeaturedProjects(index);
		res.json({ ok: true, projects });
		sendEventMessage([
			"<b>#FEATURED_PROJECT</b>",
			eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
			eventFmt`project: ${{ type: "project", id: projectData.id, name: projectData.name }}`,
			eventFmt`author: ${{ type: "user", id: index.users[authorUsername].id, username: index.users[authorUsername].username }}`
		]);
	}
);

app.delete(
	["/featured/projects/:id", "/featured-projects/:id"],
	verifyAuth,
	securityCheck,
	validateId,
	async (req, res) => {
		if (req.userRole !== "dashteam")
			return res.status(403).json({
				ok: false,
				error: "Only Dash Team can do this, what did you expect?"
			});

		const projectId = req.params.id;
		const index = req.usersIndex;

		const featuredProject = index.featuredProjects?.find((p) => String(p.id) === String(projectId));

		if (!featuredProject)
			return res.status(404).json({ ok: false, error: "Project not featured" });

		const authorProfile = index.users[featuredProject.author.username.toLowerCase()];

		index.featuredProjects = index.featuredProjects.filter(
			(p) => String(p.id) !== String(projectId)
		);

		if (authorProfile) {
			authorProfile.messages = authorProfile.messages?.filter((m) => !(m.type === "featured" && String(m.id) === String(projectId))) || [];
			authorProfile.unreadMessages = (authorProfile.unreadMessages || 1) - 1;
		}

		await storage.updateIndex(index);

		const projects = formatFeaturedProjects(index);
		res.json({ ok: true, projects });
		sendEventMessage([
			"<b>#UNFEATURED_PROJECT</b>",
			eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
			eventFmt`project: ${{ type: "project", id: featuredProject.id, name: featuredProject.name }}`,
			eventFmt`author: ${{ type: "user", id: authorProfile.id, username: authorProfile.username }}`
		]);
	}
);

app.get(["/featured/projects", "/featured-projects"], securityCheck, (req, res) => {
	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = isNaN(offset) ? 0 : Math.max(0, offset);
	const featuredProjects = (req.usersIndex.featuredProjects || []).slice(offset, offset + limit);
	const projects = formatFeaturedProjects(req.usersIndex, featuredProjects);
	res.json({
		ok: true,
		total: (req.usersIndex.featuredProjects || []).length,
		projects
	});
});

app.post("/featured/studios/:id", verifyAuth, securityCheck, validateId, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const index = req.usersIndex;
	const studio = index.studios?.[String(req.params.id)];
	if (!studio) return res.status(404).json({ ok: false, error: "Studio not found" });

	index.featuredStudios = index.featuredStudios || [];
	if (index.featuredStudios.some((featuredStudio) => String(featuredStudio.id) === String(studio.id)))
		return res.status(400).json({ ok: false, error: "Studio already featured" });

	index.featuredStudios.unshift({ id: studio.id, featuredAt: new Date().toISOString() });
	await storage.updateIndex(index);
	res.json({ ok: true, studios: formatFeaturedStudios(index) });
	sendEventMessage([
		"<b>#FEATURED_STUDIO</b>",
		eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
		eventFmt`studio: ${{ type: "studio", id: studio.id, name: studio.name || "Untitled Studio" }}`
	]);
});

app.delete("/featured/studios/:id", verifyAuth, securityCheck, validateId, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({
			ok: false,
			error: "Only Dash Team can do this, what did you expect?"
		});

	const index = req.usersIndex;
	const studioId = req.params.id;
	const featuredStudio = index.featuredStudios?.find(
		(entry) => String(entry.id) === String(studioId)
	);
	if (!featuredStudio)
		return res.status(404).json({ ok: false, error: "Studio not featured" });

	index.featuredStudios = index.featuredStudios.filter(
		(entry) => String(entry.id) !== String(studioId)
	);
	await storage.updateIndex(index);
	res.json({ ok: true, studios: formatFeaturedStudios(index) });
	sendEventMessage([
		"<b>#UNFEATURED_STUDIO</b>",
		eventFmt`admin: ${{ type: "user", id: req.user.userId, username: req.user.username }}`,
		eventFmt`studio: ${{ type: "studio", id: studioId, name: index.studios?.[String(studioId)]?.name || "Untitled Studio" }}`
	]);
});

app.get("/featured/studios", securityCheck, (req, res) => {
	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = isNaN(offset) ? 0 : Math.max(0, offset);
	const featuredStudios = (req.usersIndex.featuredStudios || []).slice(offset, offset + limit);
	const studios = formatFeaturedStudios(req.usersIndex, featuredStudios);
	res.json({
		ok: true,
		total: (req.usersIndex.featuredStudios || []).length,
		studios
	});
});
