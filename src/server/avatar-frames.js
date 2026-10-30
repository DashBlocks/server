import path from "path";

import app from "../app.js";
import * as vars from "./vars.js";
import { securityCheck } from "./util/helpers.js";

const AVATAR_FRAMES = [
    { id: "blocks" },
	{ id: "dashy" },
	{ id: "thorny-core" }
];

app.get("/avatar-frames", securityCheck, (req, res) => {
    let limit = parseInt(req.query.limit, 10);
	let offset = parseInt(req.query.offset, 10);
	limit = isNaN(limit) ? 40 : Math.min(Math.max(1, limit), 40);
	offset = isNaN(offset) ? 0 : Math.max(0, offset);

    const avatarFrames = AVATAR_FRAMES.slice(offset, offset + limit);

    res.json({
        ok: true,
        total: AVATAR_FRAMES.length,
        avatarFrames
    });
});

app.get("/avatar-frames/:id", securityCheck, (req, res) => {
    try {
        const avatarFrameId = req.params.id;
    
        if (!AVATAR_FRAMES.find((frame) => frame.id === avatarFrameId)) throw new Error();
    
        res.setHeader("Content-Type", "image/svg+xml");
        res.sendFile(path.join(vars.ASSETS_PATH, `avatar-frames/${avatarFrameId}.svg`));
    } catch (_) {
        res.status(404).json({ ok: false, error: "Avatar frame not found" });
    }
});

export { AVATAR_FRAMES };