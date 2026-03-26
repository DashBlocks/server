import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import multer from "multer";

const app = express();
const upload = multer();

app.use(
	express.json({ limit: "5mb" }),
	cors({
		origin: ["https://dashblocks.github.io", "http://localhost:3000"],
		credentials: true
	}),
	cookieParser()
);

app.options("*", cors());
app.set("trust proxy", 1);

export { upload };
export default app;
