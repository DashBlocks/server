import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import bcrypt from "bcrypt";
import { fileURLToPath } from "url";
import { Readable } from "stream";

const app = express();
dotenv.config();
const upload = multer();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BOT_TOKEN = process.env.BOT_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;
const UI_PATH = path.join(__dirname, "ui");
const PROJECTS_GROUP_ID = process.env.PROJECTS_GROUP_ID;
const GETTERS_GROUP_ID = process.env.GETTERS_GROUP_ID;
const USERS_GROUP_ID = process.env.USERS_GROUP_ID;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

app.use(
  express.json({ limit: "50mb" }),
  cors({
    origin: ["https://dashblocks.github.io", "http://localhost:3000"],
    credentials: true,
  }),
  cookieParser(),
);

async function uploadToTelegram(chatId, buffer, filename) {
  const formData = new FormData();
  formData.append("chat_id", chatId);
  formData.append("document", new Blob([buffer]), filename);

  const response = await fetch(`${TELEGRAM_API}/sendDocument`, {
    method: "POST",
    body: formData,
  });

  const result = await response.json();
  if (!result.ok) return null;
  return result.result.message_id;
}

async function fetchFromTelegram(messageId, fromChatId) {
  const forwardRes = await fetch(`${TELEGRAM_API}/forwardMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: GETTERS_GROUP_ID,
      from_chat_id: fromChatId,
      message_id: messageId,
    }),
  });
  const forwardData = await forwardRes.json();
  if (!forwardData.ok) return null;
  const fileId = forwardData.result.document.file_id;

  const filePathRes = await fetch(`${TELEGRAM_API}/getFile?file_id=${fileId}`);
  const filePathData = await filePathRes.json();
  return `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePathData.result.file_path}`;
}

app.get("/", (req, res) => {
  res.sendFile("index.html", { root: UI_PATH });
});

// Projects

app.post(
  "/save-project",
  verifyAuth,
  upload.single("file"),
  async (req, res) => {
    const { name } = req.body;
    const file = req.file;
    if (!file)
      return res.status(400).json({ ok: false, error: "No file uploaded" });

    const projectId = await uploadToTelegram(
      PROJECTS_GROUP_ID,
      file.buffer,
      `${name || "Project"}_${req.user.username}.dbp.zip`,
    );

    res.json({ ok: true, projectId });
  },
);

app.get("/get-project/:id", async (req, res) => {
  try {
    const downloadUrl = await fetchFromTelegram(
      req.params.id,
      PROJECTS_GROUP_ID,
    );
    const fileRes = await fetch(downloadUrl);

    res.setHeader("Content-Type", "application/zip");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${req.params.id}.dbp.zip"`,
    );

    Readable.fromWeb(fileRes.body).pipe(res);
  } catch (error) {
    res.status(404).json({ ok: false, error: "Project not found" });
  }
});

app.get("/upload-project", (req, res) => {
  res.sendFile("upload-project.html", { root: UI_PATH });
});

// Auth

/* app.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) throw new Error("Missing param(s)");

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const userData = JSON.stringify({ username, password: hashedPassword });
    const userId = await uploadToTelegram(USERS_GROUP_ID, Buffer.from(userData), `${username}.json`);

    res.json({ ok: true, userId });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
}); */

app.post("/auth/login", async (req, res) => {
  try {
    const { userId, password } = req.body;
    const downloadUrl = await fetchFromTelegram(userId, USERS_GROUP_ID);
    const userFileRes = await fetch(downloadUrl);
    const storedUser = await userFileRes.json();

    const isMatch = await bcrypt.compare(password, storedUser.password);

    if (isMatch) {
      const token = jwt.sign(
        { userId, username: storedUser.username },
        JWT_SECRET,
        { expiresIn: "7d" },
      );

      res.cookie("auth_token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ ok: true, username: storedUser.username, userId });
    } else {
      res
        .status(401)
        .json({ ok: false, error: "Invalid username or password" });
    }
  } catch (error) {
    res.status(404).json({ ok: false, error: error.message });
  }
});

app.post("/auth/logout", verifyAuth, (req, res) => {
  res.clearCookie("auth_token");
  res.json({ ok: true, message: "Logged out" });
});

app.get("/session", verifyAuth, (req, res) => {
  res.json({
    ok: true,
    userId: req.user.userId,
    username: req.user.username,
  });
});

const verifyAuth = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ ok: false, error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ ok: false, error: "Invalid session" });
  }
};

app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: UI_PATH });
});

app.listen(3000, () => {
  console.log("Port 3000");
});

export default app;
