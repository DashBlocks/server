import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import multer from "multer";
import { Resend } from "resend";

import * as vars from "./server/vars.js";

const app = express();
const upload = multer();
const imageUpload = multer({
	limits: { fileSize: 5 * 1024 * 1024 },
	fileFilter: (req, file, cb) => {
		if (file.mimetype && file.mimetype.startsWith("image/")) {
			cb(null, true);
		} else {
			cb(new Error("Format not supported"));
		}
	}
});
const resend = new Resend(vars.RESEND_API_KEY);

app.use(
	express.json({ limit: "2mb" }),
	cors({
		origin: ["https://dashblocks.org", "http://localhost:3000"],
		credentials: true
	}),
	cookieParser()
);

app.options("*", cors());
app.set("trust proxy", 1);

export {
	app as default,
	upload,
	imageUpload,
	resend
};
