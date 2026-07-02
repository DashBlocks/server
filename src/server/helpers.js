import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

import { JWT_SECRET, TG_BOT_TOKEN, TG_EVENTS_GROUP_ID } from "./vars.js";
import { getIndex } from "./storage.js";

const isValidUsername = (username) => {
	const regex = /^(?!\d+$)[a-zA-Z0-9-_]+$/;
	return regex.test(username) && username.length <= 20 && username.length >= 3;
};

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const validateId = (req, res, next) => {
	const id = req.params.id;
	if (!id || !/^s?\d+$/.test(id) || id.startsWith("0") || id.startsWith("s0")) {
		return res.status(400).json({ ok: false, error: "Invalid ID" });
	}
	next();
};

// https://github.com/DashBlocks/scratch-gui/blob/develop/src/containers/tw-security-manager.jsx#L27
const isTrustedUrl = (url) =>
	url.toLowerCase().startsWith("https://dashblocks.github.io") ||
    url.toLowerCase().startsWith("https://github.com/dashblocks") ||
    url.toLowerCase().startsWith("https://scratch.org") ||
    url.toLowerCase().startsWith("https://scratch.mit.edu") ||
    url.toLowerCase().startsWith("https://turbowarp.org") ||
    url.toLowerCase().startsWith("https://extensions.turbowarp.org") ||
    url.toLowerCase().startsWith("https://penguinmod.com") ||
    url.toLowerCase().startsWith("https://studio.penguinmod.com") ||
    url.toLowerCase().startsWith("https://extensions.penguinmod.com") ||
    // For development
    url.toLowerCase().startsWith("http://localhost:");

const generateVerificationCode = () =>
	Math.floor(100000 + Math.random() * 900000).toString();

const generateUserObject = (user) => {
	if (!user || typeof user !== "object") return {
		id: null,
		username: "Unknown",
		role: "dasher",
		profile: {
			avatarId: 1,
			scratchUsername: null,
			gradient: null,
			description: "",
			recommendedProject: {
				id: null,
				name: "Unknown",
				thumbnailId: 1
			},
			links: [],
			achievements: []
		},
		joinedAt: null,
		lastActive: null
	};
	return {
		id: user.id || null,
		username: user.username || "Unknown",
		role: user.role || "dasher",
		profile: {
			avatarId: user.id || 1,
			scratchUsername: user.scratchUsername || null,
			gradient: user.gradient || null,
			description: user.description || "",
			recommendedProject: {
				id: user.recommendedProject?.id || null,
				name: user.recommendedProject?.name || "Unknown",
				thumbnailId: user.recommendedProject?.id || 1
			},
			links: user.links || [],
			achievements: user.achievements || []
		},
		joinedAt: user.joinedAt || null,
		lastActive: user.lastActive || null
	};
};

const getUserIndexData = (index, target) => {
	if (/^s?\d+$/.test(target) && !target.startsWith("0") && !target.startsWith("s0")) {
		return Object.values(index.users).find((u) => String(u.id) === String(target));
	}
	return index.users[target.toLowerCase()];
};

const sendEventMessage = async (text) => {
	try {
		// eslint-disable-next-line no-console
		console.log(text);
		await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				chat_id: TG_EVENTS_GROUP_ID,
				text,
				parse_mode: "HTML"
			})
		});
	} catch (_) {/* ignore */}
};

const verifyAuth = (req, res, next) => {
	const token = req.cookies.auth_token;
	if (!token) return res.status(401).json({ ok: false, error: "Unauthorized" });

	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = decoded;
		next();
	} catch (_) {
		res.status(401).json({ ok: false, error: "Invalid session" });
	}
};

const securityCheck = async (req, res, next) => {
	try {
		const index = await getIndex();
		if (!index)
			return res
				.status(500)
				.json({ ok: false, error: "Security check failed" });

		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
		const username = req.user?.username?.toLowerCase();

		if (index.bannedIps?.includes(userIp)) {
			return res.status(403).json({ ok: false, error: "IP address banned" });
		}

		if (username) {
			const profile = index.users[username];
			if (profile?.banned) {
				return res.status(403).json({ ok: false, error: "Account banned" });
			}
			req.userRole = profile?.role || "dasher";
		}

		req.usersIndex = index;
		next();
	} catch (_) {
		res.status(500).json({ ok: false, error: "Security check failed" });
	}
};

const authLimiter = rateLimit({
	windowMs: 60 * 60 * 1000,
	max: 15,
	message: { ok: false, error: "Too many attempts, try again later" }
});

const registerLimiter = rateLimit({
	windowMs: 24 * 60 * 60 * 1000,
	max: 5,
	message: { ok: false, error: "Too many attempts, try again later" }
});

const uploadLimiter = rateLimit({
	windowMs: 60 * 60 * 1000,
	max: 10,
	message: { ok: false, error: "Upload limit reached, try again later" }
});

const uploadTimeout = rateLimit({
	windowMs: 30 * 1000,
	max: 1,
	message: { ok: false, error: "Upload timeout" }
});

export {
	isValidUsername,
	isValidEmail,
	validateId,
	isTrustedUrl,
	generateVerificationCode,
	generateUserObject,
	getUserIndexData,
	sendEventMessage,
	verifyAuth,
	securityCheck,
	authLimiter,
	registerLimiter,
	uploadLimiter,
	uploadTimeout
};
