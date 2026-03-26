import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./vars";
import { getLatestUsersIndex } from "./telegram";

const isValidUsername = (username) => {
	const regex = /^(?!\d+$)[a-zA-Z0-9-_]+$/;
	return regex.test(username) && username.length <= 20 && username.length >= 3;
};

const validateId = (req, res, next) => {
	const id = req.params.id;
	if (!id || !/^\d+$/.test(id) || id.startsWith("0")) {
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
		const index = await getLatestUsersIndex();
		if (!index)
			return res
				.status(500)
				.json({ ok: false, error: "Security check failed" });

		const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
		const username = req.user?.username?.toLowerCase();

		if (index.bannedIps.includes(userIp)) {
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

export {
	isValidUsername,
	validateId,
	isTrustedUrl,
	verifyAuth,
	securityCheck
};