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
				{
					id: projectId,
					...projectData.project,
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
	res.json({ ok: true, projects: req.usersIndex.featuredProjects || [] });
});
