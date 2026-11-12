import { commentTarget } from "./util/comment-target.js";
import app from "../app.js";
import {
	securityCheck,
	verifyAuth,
	getUserIndexData,
	escapeHTML,
	sendEventMessage,
	eventFmt
} from "./util/helpers.js";
import * as storage from "./storage.js";

const formatComment = (comment, users) => {
	const author = users.get(String(comment.authorId));
	return {
		id: comment.id,
		content: comment.content,
		threadId: comment.threadId || null,
		replyTo: comment.replyTo || null,
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

const route = "/:scope(projects|users|studios)/:id/comments";
const validateTargetId = (req, res, next) => {
	const valid = req.params.scope === "users" ? /^s?[1-9]\d*$/ : /^[1-9]\d*$/;
	if (!valid.test(req.params.id)) return res.status(400).json({ ok: false, error: "Invalid ID" });
	next();
};
const positive = value => Number.isSafeInteger(value) && value > 0;
const fail = (status, code) => Object.assign(new Error(code), { status, code });

app.get(route, securityCheck, validateTargetId, (req, res) => {
	const index = req.usersIndex;
	const target = commentTarget(index, req.params.scope, req.params.id);
	if (!target) return res.status(404).json({ ok: false, error: "Page not found" });
	const limit = Number(req.query.limit ?? 20);
	const before = Number(req.query.before);
	const thread = Number(req.query.thread);
	const after = Number(req.query.after);
	const threaded = req.query.thread !== undefined;
	if (!positive(limit) || limit > 50 ||
		(req.query.before !== undefined && (threaded || !positive(before))) ||
		(threaded && !positive(thread)) ||
		(req.query.after !== undefined && (!threaded || !positive(after))))
		return res.status(400).json({ ok: false, error: "Invalid pagination" });
	const comments = target.item.comments || [];
	const users = new Map(Object.values(index.users).map(user => [String(user.id), user]));
	res.setHeader("Cache-Control", "no-store");
	if (threaded) {
		const replies = comments.filter(entry => entry.threadId === thread && (!after || entry.id > after));
		const page = replies.slice(0, limit);
		return res.json({
			ok: true, replies: page.map(entry => formatComment(entry, users)),
			nextCursor: replies.length > limit ? page.at(-1).id : null
		});
	}
	const roots = comments.filter(entry => !entry.threadId && (!before || entry.id < before));
	const page = roots.slice(-limit).reverse().map(entry => ({
		...formatComment(entry, users), replies: [], nextReplyCursor: null
	}));
	const visible = new Map(page.map(root => [root.id, root]));
	for (const entry of comments) {
		const root = visible.get(entry.threadId);
		if (!root) continue;
		if (root.replies.length < 3) root.replies.push(formatComment(entry, users));
		else root.nextReplyCursor = root.replies.at(-1).id;
	}
	res.json({
		ok: true, enabled: index.commentsEnabled !== false, total: comments.length,
		projectOwnerId: req.params.scope === "projects" ? target.owner.id : null,
		comments: page, nextCursor: roots.length > limit ? page.at(-1).id : null
	});
});

app.post(route, verifyAuth, securityCheck, validateTargetId, async (req, res) => {
	const { content, replyToId } = req.body || {};
	if (typeof content !== "string" || !content.trim() || content.length > 500 ||
		(replyToId !== undefined && !positive(replyToId)) ||
		Object.keys(req.body).some(key => key !== "content" && key !== "replyToId"))
		return res.status(400).json({ ok: false, error: "Invalid comment" });
	try {
		const { scope, id: pageId } = req.params;
		const result = await storage.mutateIndex(index => {
			const user = index.users[req.user.username.toLowerCase()];
			if (!user || String(user.id) !== String(req.user.userId) || user.banned) throw fail(403, "ACCOUNT_UNAVAILABLE");
			const target = commentTarget(index, scope, pageId);
			if (!target) throw fail(404, "PAGE_NOT_FOUND");
			const item = target.item;
			if (index.commentsEnabled === false) throw fail(403, "COMMENTS_DISABLED");
			const comments = item.comments ||= [];
			const parent = replyToId && comments.find(entry => entry.id === replyToId);
			if (replyToId && !parent) throw fail(404, "COMMENT_NOT_FOUND");
			const now = Date.now();
			const remaining = 10000 - (now - (user.lastCommentAt || 0));
			if (remaining > 0) throw Object.assign(fail(429, "RATE_LIMIT"), { retryAfter: Math.ceil(remaining / 1000) });
			const id = item.nextCommentId || (comments.at(-1)?.id || 0) + 1;
			if (!positive(id) || id >= Number.MAX_SAFE_INTEGER) throw new Error("Comment ID limit reached");
			const comment = {
				id, authorId: user.id, username: user.username, content: content.trim(), createdAt: new Date(now).toISOString(),
				...(parent ? { threadId: parent.threadId || parent.id, replyTo: {
					id: parent.id, authorId: parent.authorId, username: parent.username
				} } : {})
			};
			comments.push(comment);
			item.nextCommentId = id + 1;
			user.lastCommentAt = now;
			const recipient = parent ? getUserIndexData(index, parent.authorId) : target.owner;
			const page = { id: item.id, name: item.name || item.username };
			if (recipient && String(recipient.id) !== String(user.id)) {
				const type = { projects: "project-commented", users: "profile-commented", studios: "studio-commented" }[scope];
				recipient.messages = [{
					type: parent ? "comment-replied" : type, scope, target: page,
					...(scope === "projects" ? { project: page } : {}),
					commentId: id, user: { id: user.id, username: user.username }, date: comment.createdAt
				}, ...(recipient.messages || [])];
				recipient.unreadMessages = (recipient.unreadMessages || 0) + 1;
			}
			return { ok: true, comment: formatComment(comment, new Map([[String(user.id), user]])), total: comments.length, page };
		});
		const { page, ...body } = result;
		const type = { projects: "project", users: "user", studios: "studio" }[scope];
		const subject = { type, id: page.id, name: page.name, username: escapeHTML(page.name) };
		const author = { type: "user", id: body.comment.author.id, username: escapeHTML(body.comment.author.username) };
		sendEventMessage([
			`<b>#${type.toUpperCase()}_COMMENTED</b>`,
			`${type}: ${eventFmt`${subject}`}`,
			eventFmt`comment author: ${author}`,
			`content: ${escapeHTML(body.comment.content)}`
		]);
		res.status(201).json(body);
	} catch (error) {
		if (error.retryAfter) res.setHeader("Retry-After", error.retryAfter);
		res.status(error.status || 500).json({ ok: false, code: error.status ? error.code : undefined,
			error: error.status ? error.message : "Failed to publish comment", retryAfter: error.retryAfter });
	}
});

app.delete(route + "/:commentId", verifyAuth, securityCheck, validateTargetId, async (req, res) => {
	const commentId = Number(req.params.commentId);
	if (!positive(commentId) || String(commentId) !== req.params.commentId)
		return res.status(400).json({ ok: false, error: "Invalid comment ID" });
	try {
		const result = await storage.mutateIndex(index => {
			const user = index.users[req.user.username.toLowerCase()];
			if (!user || String(user.id) !== String(req.user.userId) || user.banned) throw fail(403, "ACCOUNT_UNAVAILABLE");
			const { scope, id } = req.params;
			const target = commentTarget(index, scope, id);
			if (!target) throw fail(404, "PAGE_NOT_FOUND");
			const comments = target.item.comments || [];
			const entry = comments.find(comment => comment.id === commentId);
			if (!entry) throw Object.assign(fail(404, "COMMENT_NOT_FOUND"), { total: comments.length });
			if (user.role !== "dashteam" && String(entry.authorId) !== String(user.id) &&
				!(scope === "projects" && String(target.owner.id) === String(user.id))) throw fail(403, "FORBIDDEN");
			target.item.nextCommentId ||= (comments.at(-1)?.id || 0) + 1;
			const removed = new Set([commentId]);
			for (const row of comments) {
				if (removed.has(row.replyTo?.id) || removed.has(row.threadId)) removed.add(row.id);
			}
			target.item.comments = comments.filter(row => !removed.has(row.id));
			return { ok: true, commentId, removedIds: [...removed], total: target.item.comments.length };
		});
		res.json(result);
	} catch (error) {
		res.status(error.status || 500).json({ ok: false, code: error.status ? error.code : undefined,
			total: error.total, error: error.status ? error.message : "Failed to delete comment" });
	}
});
