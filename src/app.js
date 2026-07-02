import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import multer from "multer";
import { Resend } from "resend";

import * as vars from "./server/vars.js";

const app = express();
const upload = multer();
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
	resend
};
