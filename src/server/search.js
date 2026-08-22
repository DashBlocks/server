import app from "../app.js";
import { securityCheck, searchLimiter, searchTimeout } from "./helpers.js";

// "d-*" - descending sort methods
// "a-*" - ascending sort methods
const SORT_METHODS = {
	"d-upload": (p1, p2) => (
		new Date(p2.uploadedAt || 0).getTime() -
			new Date(p1.uploadedAt || 0).getTime()
	),
	"a-upload": function(p1, p2) {
		return this["d-upload"](p1, p2) * -1;
	},
	"d-views": (p1, p2) => (p2.stats?.views || 0) - (p1.stats?.views || 0),
	"d-fires": (p1, p2) => (p2.stats?.fires || 0) - (p1.stats?.fires || 0),
	"d-forks": (p1, p2) => (p2.stats?.forks || 0) - (p1.stats?.forks || 0)
};

const SEARCH_PARAMS_DEFS = {
	author: {
		priority: 1,
		get: (index, paramValue) => {
			const userProfile = Object.values(index.users).find((userProfile) => (
				(userProfile.username || "").toLowerCase() === paramValue.toLowerCase() ||
				userProfile.id === Number(paramValue)
			));
			return {
				projects: userProfile?.projects,
				userProfile
			};
		},
		filterFn: (_, userProfile, __, paramValue) => (
			(userProfile.username || "").toLowerCase() === paramValue.toLowerCase() ||
			userProfile.id === Number(paramValue)
		)
	},
	featured: {
		priority: 2,
		filterFn: (project, _, index) => (
			index.featuredProjects &&
			index.featuredProjects.some((featuredProject) => featuredProject.id === project.id)
		)
	},
	forksof: {
		priority: 2,
		filterFn: (project, _, __, paramValue) => project.parentId === Number(paramValue)
	},
	"-author": {
		priority: 3,
		userMatch: (userProfile, paramValue) => (
			(userProfile.username || "").toLowerCase() !== paramValue.toLowerCase() &&
			userProfile.id !== Number(paramValue)
		),
		filterFn: (_, userProfile, __, paramValue) => (
			(userProfile.username || "").toLowerCase() !== paramValue.toLowerCase() &&
			userProfile.id !== Number(paramValue)
		)
	},
	"-featured": {
		priority: 3,
		filterFn: (project, _, index) => (
			!index.featuredProjects ||
			index.featuredProjects.every((featuredProject) => featuredProject.id !== project.id)
		)
	},
	"-forksof": {
		priority: 3,
		filterFn: (project, _, __, paramValue) => project.parentId !== Number(paramValue)
	},
	"-fork": {
		priority: 3,
		filterFn: (project, _, __, paramValue) => !!project.parentId
	}
};

app.get("/search/projects", searchLimiter, searchTimeout, securityCheck, async (req, res) => {
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
		let sortMethod = null;
		const searchParams = [];
		const searchTerm = q.trim()
			.replace(paramRegex, (substr, paramName, paramValue) => {
				if (paramName === "sort" && paramValue in SORT_METHODS) {
					sortMethod = paramValue;
					return "";
				} else if (paramName in SEARCH_PARAMS_DEFS) {
					searchParams.push([paramName, paramValue]);
					return "";
				} else {
					return substr;
				}
			})
			.toLowerCase();
		if (!sortMethod) sortMethod = "d-upload";
		searchParams.sort(([paramName1], [paramName2]) =>
			SEARCH_PARAMS_DEFS[paramName1].priority - SEARCH_PARAMS_DEFS[paramName2].priority);
		const priorGetterParam = searchParams.find(([paramName]) => SEARCH_PARAMS_DEFS[paramName].get);
		const userMatchParams = searchParams.filter(([paramName]) => SEARCH_PARAMS_DEFS[paramName].userMatch);

		const results = [];

		if (priorGetterParam) {
			const { projects, userProfile } =
				SEARCH_PARAMS_DEFS[priorGetterParam[0]].get(index, priorGetterParam[1]);
			if (projects.length > 0) {
				const filterParams = searchParams.filter((param) => param !== priorGetterParam);

				const authorUsername = (userProfile.username || "").toLowerCase();
				const authorUsernameMatch = authorUsername.includes(searchTerm);

				projects.forEach((project) => {
					let projectMatch = true;
					for (let i = 0; i < filterParams.length && projectMatch; i++) {
						projectMatch = SEARCH_PARAMS_DEFS[filterParams[i][0]]
							.filterFn(project, userProfile, index, filterParams[i][1]);
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
								fires: project.stats?.fires || 0,
								forks: project.stats?.forks || 0
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
			}
		} else {
			const filterParams = searchParams.filter((param) => (
				param !== priorGetterParam &&
				!SEARCH_PARAMS_DEFS[param[0]].userMatch
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
							.filterFn(project, userProfile, index, filterParams[i][1]);
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
								fires: project.stats?.fires || 0,
								forks: project.stats?.forks || 0
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

		results.sort(SORT_METHODS[sortMethod]);
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
