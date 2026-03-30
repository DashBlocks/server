import app from "../app.js";
import { validateId, securityCheck, verifyAuth } from "./helpers.js";
import { updateUsersIndex } from "./telegram.js";

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

		const projectId = Number(req.params.id);
		const index = req.usersIndex;

		if (!index.featuredProjects) index.featuredProjects = [];

		const projectReq = await fetch(
			`https://dashblocks-server.vercel.app/projects/${projectId}`
		);
		if (!projectReq.ok)
			return res.status(404).json({ ok: false, error: "Project not found" });
		const projectData = await projectReq.json();

		if (!index.featuredProjects.find((p) => p.id === projectId)) {
			index.featuredProjects = [
				// Not adding all the data here since it would be
				// redundant and we can just fetch it when needed,
				// also prevents stale data
				{
					id: projectId,
					name: projectData?.name || "Unknown",
					author: {
						id: projectData?.author?.id || null,
						username: projectData?.author?.username || "Unknown",
						profile: {
							avatarId: projectData?.author?.profile?.avatarId || 1,
						},
						joinedAt: projectData?.author?.joinedAt || null
					},
					thumbnailId: projectData?.thumbnailId || 1,
					fileSize: projectData?.fileSize || null,
					uploadedAt: projectData?.uploadedAt || null,
					featuredAt: new Date().toISOString()
				},
				...index.featuredProjects
			];
			await updateUsersIndex(index);
		}

		res.json({
			ok: true,
			projects: index.featuredProjects || []
		});
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

		const projectId = Number(req.params.id);
		const index = req.usersIndex;

		if (index.featuredProjects) {
			index.featuredProjects = index.featuredProjects.filter(
				(p) => p.id !== projectId
			);
			await updateUsersIndex(index);
		}

		res.json({ ok: true, projects: index.featuredProjects || [] });
	}
);

app.get("/featured-projects", securityCheck, (req, res) => {
	let projects = req.usersIndex.featuredProjects || [];
	projects = projects.map((p) => ({
		id: p?.id || null,
		name: p?.name || "Unknown",
		author: {
			id: p.author?.id || null,
			username: p.author?.username || "Unknown",
			profile: {
				avatarId: p.author?.profile?.avatarId || 1
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
