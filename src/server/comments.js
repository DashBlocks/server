import app from "../app.js";
import { securityCheck, verifyAuth, validateId } from "./helpers.js";
import * as storage from "./storage.js";
import { sendEventMessage, eventFmt } from "./helpers.js";

const formatComment = (comment, users) => {
	const author = users.get(String(comment.authorId));
	return {
		id: comment.id,
		content: comment.content,
		createdAt: comment.createdAt,
		author: {
			id: author?.id || null,
			username: author?.username || comment.username,
			avatarId: author?.id || 1,
			avatarFrame: author?.avatarFrame || null
		}
	};
};

app.get("/comments/settings", securityCheck, (req, res) => {
	res.setHeader("Cache-Control", "no-store");
	res.json({ ok: true, enabled: req.usersIndex.commentsEnabled !== false });
});

app.patch("/comments/settings", verifyAuth, securityCheck, async (req, res) => {
	if (req.userRole !== "dashteam")
		return res.status(403).json({ ok: false, error: "Only Dash Team can do this," });
	if (typeof req.body?.enabled !== "boolean")
		return res.status(400).json({ ok: false, error: "enabled must be a boolean" });

	try {
		const result = await storage.mutateIndex((index) => {
			const user = index.users[req.user.username.toLowerCase()];
			if (!user || String(user.id) !== String(req.user.userId) || user.banned || user.role !== "dashteam")
				throw Object.assign(new Error("Only Dash Team can do this, what did you expect?"), { status: 403 });
			index.commentsEnabled = req.body.enabled;
			return { status: 200, body: { ok: true, enabled: index.commentsEnabled } };
		});
		res.status(result.status).json(result.body);
	} catch (error) {
		res.status(error.status || 500).json({
			ok: false,
			error: error.status ? error.message : "Failed to update comment settings"
		});
	}
});

app.get("/projects/:id/comments", securityCheck, validateId, (req, res) => {
	const index = req.usersIndex;
	const project = storage.findProjectById(index, req.params.id);
	if (!project) return res.status(404).json({ ok: false, error: "Project not found" });

	const limit = req.query.limit === undefined ? 20 : Number(req.query.limit);
	const before = req.query.before === undefined ? null : Number(req.query.before);
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
		(before !== null && (!Number.isSafeInteger(before) || before < 1)))
		return res.status(400).json({ ok: false, error: "Invalid pagination" });

	const comments = project.comments || [];
	let end = comments.length;
	if (before !== null) {
		let start = 0;
		while (start < end) {
			const middle = Math.floor((start + end) / 2);
			if (comments[middle].id < before) start = middle + 1;
			else end = middle;
		}
	}
	const start = Math.max(0, end - limit);
	const page = comments.slice(start, end).reverse();
	const users = new Map(Object.values(index.users).map(user => [String(user.id), user]));
	res.setHeader("Cache-Control", "no-store");
	res.json({
		ok: true,
		enabled: index.commentsEnabled !== false,
		total: comments.length,
		comments: page.map(comment => formatComment(comment, users)),
		nextCursor: start > 0 ? page[page.length - 1].id : null
	});
});

app.post("/projects/:id/comments", verifyAuth, securityCheck, validateId, async (req, res) => {
	if (typeof req.body?.content !== "string" || !req.body.content.trim() || req.body.content.length > 500)
		return res.status(400).json({ ok: false, error: "Comment must contain 1 to 500 characters" });
	if (Object.keys(req.body).some(key => key !== "content"))
		return res.status(400).json({ ok: false, error: "Only content is supported" });

	try {
		const result = await storage.mutateIndex((index) => {
			const user = index.users[req.user.username.toLowerCase()];
			if (!user || String(user.id) !== String(req.user.userId) || user.banned)
				throw Object.assign(new Error("Account unavailable"), { status: 403 });
			const project = storage.findProjectById(index, req.params.id);
			if (!project) throw Object.assign(new Error("Project not found"), { status: 404 });
			if (index.commentsEnabled === false)
				throw Object.assign(new Error("Commenting is disabled"), { status: 403, code: "COMMENTS_DISABLED" });
			const now = Date.now();
			const remaining = 10000 - (now - (user.lastCommentAt || 0));
			if (remaining > 0)
				throw Object.assign(new Error("Please wait before commenting again"), {
					status: 429,
					retryAfter: Math.ceil(remaining / 1000)
				});
			if (!project.comments) project.comments = [];
			const id = project.nextCommentId || (project.comments.at(-1)?.id || 0) + 1;
			if (!Number.isSafeInteger(id) || id < 1 || id >= Number.MAX_SAFE_INTEGER)
				throw new Error("Comment ID limit reached");
			const comment = {
				id,
				authorId: user.id,
				username: user.username,
				content: req.body.content.trim(),
				createdAt: new Date(now).toISOString()
			};
			project.comments.push(comment);
			project.nextCommentId = id + 1;
			user.lastCommentAt = now;
			sendEventMessage([
				"<b>#PROJECT_COMMENTED</b>",
				eventFmt`project: ${{ type: "project", id: project.id, name: project.name }}`,
				eventFmt`comment author: ${{ type: "user", id: user.id, username: user.username }}`
			]);
			return {
				status: 201,
				body: {
					ok: true,
					comment: formatComment(comment, new Map([[String(user.id), user]])),
					total: project.comments.length
				}
			};
		});
		res.status(result.status).json(result.body);
	} catch (error) {
		if (error.retryAfter) res.setHeader("Retry-After", error.retryAfter);
		res.status(error.status || 500).json({
			ok: false,
			error: error.status ? error.message : "Failed to publish comment",
			...(error.code === "COMMENTS_DISABLED" ? { code: error.code } : {}),
			...(error.retryAfter ? { retryAfter: error.retryAfter } : {})
		});
	}
});
