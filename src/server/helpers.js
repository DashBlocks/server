import jwt from "jsonwebtoken";
import JSZip from "jszip";
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

const validateProjectZip = async (file, userRole) => {
	if (!file)
		return { ok: false, error: "No file uploaded" };
 
	const zip = await JSZip.loadAsync(file.buffer);
	const projectData = await zip.file("project.json")?.async("string");
	if (!projectData)
		return { ok: false, error: "project.json not found" };
 
	const projectJson = JSON.parse(projectData);
	const hasCustomExtensions = Object.values(
		projectJson.extensionURLs || {}
	).some(
		(ext) =>
			(ext.startsWith("http") || ext.startsWith("data")) &&
			!isTrustedUrl(ext)
	);
	if (hasCustomExtensions && userRole === "dasher")
		return { ok: false, error: "Custom extensions require Dasher+ role" };
 
	const maxProjectSize = userRole === "dash-supporter" ? 250 * 1024 * 1024 : 75 * 1024 * 1024;
	if (file.size > maxProjectSize)
		return {
			ok: false,
			error: `Project size limit is ${userRole === "dash-supporter" ? "250MB" : "75MB - donate Dash to increase it up to 250MB! https://dashblocks.org/donate"}`
		};
 
	return { ok: true };
};

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
			achievements: [],
			stats: {
				projects: 0,
				followers: 0,
				following: 0
			},
			unreadMessages: 0
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
			achievements: user.achievements || [],
			stats: {
				projects: user.projects?.length || 0,
				followers: user.followers?.length || 0,
				following: user.following?.length || 0
			},
			unreadMessages: user.unreadMessages || 0
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

const escapeHTML = (unsafe) => {
	if (!unsafe) return "";
	return unsafe.replace(/[&<>"'`]/g, (match) => {
		const map = {
			"&": "&amp;",
			"<": "&lt;",
			">": "&gt;",
			"\"": "&quot;",
			"'": "&#x27;",
			"`": "&#x60;"
		};
		return map[match];
	});
};

const sendEventMessage = async (message) => {
	try {
		await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				chat_id: TG_EVENTS_GROUP_ID,
				text: Array.isArray(message) ? message.join("\n") : message,
				parse_mode: "HTML",
				link_preview_options: { is_disabled: true }
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

const searchLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 25,
	message: { ok: false, error: "Search limit reached, try again in 15 minutes" }
});

const projectUploadTimeout = rateLimit({
	windowMs: 15 * 1000,
	max: 1,
	message: { ok: false, error: "Upload timeout, retry in a short moment" }
});

const thumbnailUploadTimeout = rateLimit({
	windowMs: 15 * 1000,
	max: 1,
	message: { ok: false, error: "Upload timeout, retry in a short moment" }
});

const avatarUploadTimeout = rateLimit({
	windowMs: 15 * 1000,
	max: 1,
	message: { ok: false, error: "Upload timeout, retry in a short moment" }
});

const searchTimeout = rateLimit({
	windowMs: 5 * 1000,
	max: 1,
	message: { ok: false, error: "Upload timeout, retry in a short moment" }
});

export {
	isValidUsername,
	isValidEmail,
	validateId,
	isTrustedUrl,
	validateProjectZip,
	generateVerificationCode,
	generateUserObject,
	getUserIndexData,
	escapeHTML,
	sendEventMessage,
	verifyAuth,
	securityCheck,
	authLimiter,
	registerLimiter,
	uploadLimiter,
	searchLimiter,
	projectUploadTimeout,
	thumbnailUploadTimeout,
	avatarUploadTimeout,
	searchTimeout
};
