import app from "../app.js";
import { validateId, securityCheck, verifyAuth } from "./helpers.js";
import { updateIndex } from "./storage.js";

app.post(
	"/featured-projects/:id",
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
			`https://dashblocks-server.vercel.app/projects/${projectId}`
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
		}

		await updateIndex(index);

		let projects = index.featuredProjects || [];
		projects = projects.map((p) => ({
			id: p?.id || null,
			name: p?.name || "Unknown",
			author: {
				id: p.author?.id || null,
				username: p.author?.username || "Unknown",
				profile: {
					avatarId: p.author?.id || 1
				},
				joinedAt: p.author?.joinedAt || null
			},
			thumbnailId: p?.thumbnailId || 1,
			fileSize: p?.fileSize || null,
			uploadedAt: p?.uploadedAt || null,
			featuredAt: p?.featuredAt || null
		}));
		res.json({ ok: true, projects });
	}
);

app.delete(
	"/featured-projects/:id",
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
		}
        
		await updateIndex(index);

		let projects = index.featuredProjects || [];
		projects = projects.map((p) => ({
			id: p?.id || null,
			name: p?.name || "Unknown",
			author: {
				id: p.author?.id || null,
				username: p.author?.username || "Unknown",
				profile: {
					avatarId: p.author?.id || 1
				},
				joinedAt: p.author?.joinedAt || null
			},
			thumbnailId: p?.thumbnailId || 1,
			fileSize: p?.fileSize || null,
			uploadedAt: p?.uploadedAt || null,
			featuredAt: p?.featuredAt || null
		}));
		res.json({ ok: true, projects });
	}
);

app.get("/featured-projects", securityCheck, (req, res) => {
	let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
	offset = isNaN(offset) ? 0 : Math.max(0, offset);
	let projects = (req.usersIndex.featuredProjects || []).slice(offset, offset + limit);
	// Not showing all the data here since it would be
	// redundant and we can just fetch it when needed,
	// also prevents stale data
	projects = projects.map((p) => ({
		id: p?.id || null,
		name: p?.name || "Unknown",
		author: {
			id: p.author?.id || null,
			username: p.author?.username || "Unknown",
			profile: {
				avatarId: p.author?.id || 1
			},
			joinedAt: p.author?.joinedAt || null
		},
		thumbnailId: p?.thumbnailId || 1,
		fileSize: p?.fileSize || null,
		uploadedAt: p?.uploadedAt || null,
		featuredAt: p?.featuredAt || null
	}));
	res.json({ ok: true, projects });
});
