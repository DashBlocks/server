import app from "../app.js";
import { securityCheck } from "./helpers.js";

const SEARCH_PARAMS_DEFS = {
	featured: {
		priority: 1,
		get: (index, paramValue) => ({
			projects: index.featuredProjects,
			userless: false
		}),
		userlessFilterFn: (project, _, index) => (
			index.featuredProjects &&
			index.featuredProjects.some((featuredProject) => featuredProject.id === project.id)
		),
		filterFn: (project, index) => (
			index.featuredProjects &&
			index.featuredProjects.some((featuredProject) => featuredProject.id === project.id)
		)
	},
	author: {
		priority: 2,
		get: (index, paramValue) => {
			const userProfile = Object.values(index.users).find((userProfile) => (
				(userProfile.username || "").toLowerCase() === paramValue.toLowerCase() ||
				userProfile.id === Number(paramValue)
			));
			return {
				projects: userProfile?.projects,
				userless: true,
				userProfile
			};
		},
		userlessFilterFn: (_, userProfile, __, paramValue) => (
			(userProfile.username || "").toLowerCase() === paramValue.toLowerCase() ||
			userProfile.id === Number(paramValue)
		),
		filterFn: (project, _, paramValue) => (
			project.author.username.toLowerCase() === paramValue.toLowerCase() ||
			project.author.id === Number(paramValue)
		)
	},
	"-featured": {
		priority: 3,
		userlessFilterFn: (project, _, index) => (
			!index.featuredProjects ||
			index.featuredProjects.every((featuredProject) => featuredProject.id !== project.id)
		),
		filterFn: (project, index) => (
			!index.featuredProjects ||
			index.featuredProjects.every((featuredProject) => featuredProject.id !== project.id)
		)
	},
	"-author": {
		priority: 3,
		userMatch: (userProfile, paramValue) => (
			(userProfile.username || "").toLowerCase() !== paramValue.toLowerCase() &&
			userProfile.id !== Number(paramValue)
		),
		userlessFilterFn: (_, userProfile, __, paramValue) => (
			(userProfile.username || "").toLowerCase() !== paramValue.toLowerCase() &&
			userProfile.id !== Number(paramValue)
		),
		filterFn: (project, _, paramValue) => (
			project.author.username.toLowerCase() !== paramValue.toLowerCase() &&
			project.author.id !== Number(paramValue)
		)
	}
};

app.get("/search/projects", securityCheck, async (req, res) => {
	try {
		const { q } = req.query;
		let limit = parseInt(req.query.limit, 10);
		let offset = parseInt(req.query.offset, 10);
		limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40); 
		offset = isNaN(offset) ? 0 : Math.max(0, offset);
		const index = req.usersIndex;

		if (!q || typeof q !== "string" || q.trim().length === 0)
			return res.status(400).json({ ok: false, error: "IDK what to search :P" });
		if (q.trim().length > 200)
			return res.status(400).json({ ok: false, error: "Query is too long (maximum length 200, excluding trimmed white spaces)" });

		const paramRegex = /\s*(-?[a-z]+):(\S*)\s*/gi;
		const searchParams = [];
		const searchTerm = q.trim()
			.replace(paramRegex, (_, paramName, paramValue) => {
				if (paramName in SEARCH_PARAMS_DEFS) searchParams.push([paramName, paramValue]);
				return "";
			})
			.toLowerCase();
		searchParams.sort(([paramName1], [paramName2]) =>
			SEARCH_PARAMS_DEFS[paramName1].priority - SEARCH_PARAMS_DEFS[paramName2].priority);
		if (req.userRole === "dashteam") console.log(
			`searchTerm - ${searchTerm}\n` +
			`searchParams - ${JSON.stringify(searchParams)}`
		);
		const priorGetterParam = searchParams.find(([paramName]) => SEARCH_PARAMS_DEFS[paramName].get);
		const userMatchParams = searchParams.filter(([paramName]) => SEARCH_PARAMS_DEFS[paramName].userMatch);

		const results = [];

		if (priorGetterParam) {
			const { projects, userless, userProfile } =
				SEARCH_PARAMS_DEFS[priorGetterParam[0]].get(index, priorGetterParam[1]);
			if (projects.length > 0) {
				const filterParams = searchParams.filter((param) => param !== priorGetterParam);

				let userlessAuthorUsernameMatch = false;
				if (userless) {
					const authorUsername = (userProfile.username || "").toLowerCase();
					userlessAuthorUsernameMatch = authorUsername.includes(searchTerm);
				}

				projects.forEach((project) => {
					let projectMatch = true;
					for (let i = 0; i < filterParams.length && projectMatch; i++) {
						projectMatch = userless
							? SEARCH_PARAMS_DEFS[filterParams[i][0]]
								.userlessFilterFn(project, userProfile, index, filterParams[i][1])
							: SEARCH_PARAMS_DEFS[filterParams[i][0]]
								.filterFn(project, index, filterParams[i][1]);
					}
					if (!projectMatch) return;

					const projectName = (project.name || "").toLowerCase();
					const projectDescription = (project.description || "").toLowerCase();

					const nameMatch = projectName.includes(searchTerm);
					const descriptionMatch = projectDescription.includes(searchTerm);

					let authorUsernameMatch = false;
					if (!userless) {
						const authorUsername = (project.author.username || "").toLowerCase();
						authorUsernameMatch = authorUsername.includes(searchTerm);
					}

					if (
						nameMatch ||
						descriptionMatch ||
						userlessAuthorUsernameMatch ||
						authorUsernameMatch
					) {
						results.push({
							id: project.id || null,
							name: project.name || "Untitled",
							description: project.description || "",
							thumbnailId: project.id || 1,
							stats: {
								views: project.stats?.views || 0,
								fires: project.stats?.fires || 0
							},
							author: {
								id: (userless ? userProfile.id : project.author.id) || null,
								username: (userless ? userProfile.username : project.author.username) || "Unknown",
								profile: { avatarId: (userless ? userProfile.id : project.author.id) || 1 },
								joinedAt: (userless ? userProfile.joinedAt : project.author.joinedAt) || null
							},
							uploadedAt: project.uploadedAt || null
						});
					}
				});
			}
		} else {
			const filterParams = searchParams.filter((param) => (
				param !== priorGetterParam &&
				!userMatchParams.includes(param)
			));
			Object.values(index.users).forEach((userProfile) => {
				if (!userProfile.projects || userProfile.projects.length === 0) return;

				let authorMatch = true;
				for (let i = 0; i < userMatchParams.length && authorMatch; i++) {
					authorMatch = SEARCH_PARAMS_DEFS[userMatchParams[i][0]]
						.userMatch(index, userMatchParams[i][1]);
				}
				if (!authorMatch) return;

				const authorUsername = (userProfile.username || "").toLowerCase();
				const authorUsernameMatch = authorUsername.includes(searchTerm);

				userProfile.projects.forEach((project) => {
					let projectMatch = true;
					for (let i = 0; i < filterParams.length && projectMatch; i++) {
						projectMatch = SEARCH_PARAMS_DEFS[filterParams[i][0]]
							.filterFn(project, index, filterParams[i][1]);
					}
					if (!projectMatch) return;

					const projectName = (project.name || "").toLowerCase();
					const projectDescription = (project.description || "").toLowerCase();

					const nameMatch = projectName.includes(searchTerm);
					const descriptionMatch = projectDescription.includes(searchTerm);

					if (nameMatch || descriptionMatch || authorUsernameMatch) {
						results.push({
							id: project.id || null,
							name: project.name || "Untitled",
							description: project.description || "",
							thumbnailId: project.id || 1,
							stats: {
								views: project.stats?.views || 0,
								fires: project.stats?.fires || 0
							},
							author: {
								id: userProfile.id || null,
								username: userProfile.username || "Unknown",
								profile: { avatarId: userProfile.id || 1 },
								joinedAt: userProfile.joinedAt || null
							},
							uploadedAt: project.uploadedAt || null
						});
					}
				});
			});
		}

		// Newest first
		results.sort((a, b) => {
			const dateA = new Date(a.uploadedAt || 0).getTime();
			const dateB = new Date(b.uploadedAt || 0).getTime();
			return dateB - dateA;
		});

		const finalResults = results.slice(offset, offset + limit);

		res.json({
			ok: true,
			total: results.length,
			results: finalResults
		});
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to search projects" });
	}
});
