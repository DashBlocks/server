import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import rateLimit from "express-rate-limit";
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
const USERS_INDEX_GROUP_ID = process.env.USERS_INDEX_GROUP_ID;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

const forbiddenUsernames = ["unknown"];

app.use(
  express.json({ limit: "50mb" }),
  cors({
    origin: ["https://dashblocks.github.io", "http://localhost:3000"],
    credentials: true,
  }),
  cookieParser(),
);

app.options("*", cors());
app.set("trust proxy", 1);

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { ok: false, error: "Too many attempts, try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { ok: false, error: "Upload limit reached, try again later" },
});

// Helpers

const isValidUsername = (username) => {
  const regex = /^[a-zA-Z0-9-_]+$/;
  return regex.test(username);
};

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

async function getLatestUsersIndex() {
  const chatRes = await fetch(
    `${TELEGRAM_API}/getChat?chat_id=${USERS_INDEX_GROUP_ID}`,
  );
  const chatData = await chatRes.json();
  const pinnedId = chatData.result?.pinned_message?.message_id;

  if (!pinnedId) return { usernames: [] };

  const downloadUrl = await fetchFromTelegram(pinnedId, USERS_INDEX_GROUP_ID);
  const fileRes = await fetch(downloadUrl);
  return await fileRes.json();
}

async function updateUsersIndex(username) {
  const data = await getLatestUsersIndex();
  data.usernames.push(username.toLowerCase());

  const msgId = await uploadToTelegram(
    USERS_INDEX_GROUP_ID,
    Buffer.from(JSON.stringify(data)),
    "users_index.json",
  );

  await fetch(`${TELEGRAM_API}/pinChatMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: USERS_INDEX_GROUP_ID,
      message_id: msgId,
      disable_notification: true,
    }),
  });
}

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

app.get("/", (req, res) => {
  res.sendFile("index.html", { root: UI_PATH });
});

// Projects

app.post(
  "/save-project",
  verifyAuth,
  uploadLimiter,
  upload.single("file"),
  async (req, res) => {
    const { name } = req.body;
    if (name && name.includes("_"))
      return res
        .status(400)
        .json({ ok: false, error: "Project name cannot contain underscores" });

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

app.get("/projects/:id", async (req, res) => {
  try {
    const projectId = req.params.id;
    const forwardRes = await fetch(`${TELEGRAM_API}/forwardMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: GETTERS_GROUP_ID,
        from_chat_id: PROJECTS_GROUP_ID,
        message_id: projectId,
      }),
    });

    const data = await forwardRes.json();
    if (!data.ok || !data.result.document)
      return res.status(404).json({ ok: false, error: "Project not found" });

    const doc = data.result.document;
    const fileName = doc.file_name || "";

    const lastUnderscoreIndex = fileName.lastIndexOf("_");

    let projectName = "Untitled";
    let authorPart = "Unknown";
    if (lastUnderscoreIndex !== -1) {
      projectName = fileName.substring(0, lastUnderscoreIndex);
      authorPart = fileName
        .substring(lastUnderscoreIndex + 1)
        .replace(".dbp.zip", "");
    } else if (fileName.endsWith(".dbp.zip")) {
      projectName =
        fileName.replace(".dbp.zip", "") !== ""
          ? fileName.replace(".dbp.zip", "")
          : "Untitled";
    }
    const unixTimestamp = data.result.forward_date;
    const isoDate = unixTimestamp
      ? new Date(unixTimestamp * 1000).toISOString()
      : null;
    res.json({
      ok: true,
      project: {
        id: projectId,
        name: projectName,
        author: {
          username: authorPart,
        },
        size: doc.file_size,
        uploadedAt: isoDate,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ ok: false, error: "Failed to fetch project metadata" });
  }
});

app.get("/upload-project", (req, res) => {
  res.sendFile("upload-project.html", { root: UI_PATH });
});

// Users & Auth

app.get("/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const downloadUrl = await fetchFromTelegram(userId, USERS_GROUP_ID);
    if (!downloadUrl)
      return res.status(404).json({ ok: false, error: "User not found" });

    const userFileRes = await fetch(downloadUrl);
    const storedUser = await userFileRes.json();

    res.json({
      ok: true,
      user: {
        id: userId,
        username: storedUser.username,
        joinedAt: storedUser.joinedAt || null,
      },
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: "Failed to fetch user metadata" });
  }
});

app.post("/auth/register", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !isValidUsername(username)) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid username symbols" });
    }

    if (forbiddenUsernames.includes(username.toLowerCase())) {
      return res
        .status(400)
        .json({ ok: false, error: "You cannot use this username" });
    }

    const index = await getLatestUsersIndex();
    if (index.usernames.includes(username.toLowerCase())) {
      return res
        .status(400)
        .json({ ok: false, error: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = JSON.stringify({
      username,
      password: hashedPassword,
      joinedAt: new Date().toISOString(),
    });

    const userId = await uploadToTelegram(
      USERS_GROUP_ID,
      Buffer.from(userData),
      `${username}.json`,
    );
    if (!userId) throw new Error("Failed to store user");

    await updateUsersIndex(username);

    const token = jwt.sign({ userId, username }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    res.json({ ok: true, userId, username });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

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
        sameSite: "none",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/",
      });
      res.json({ ok: true, username: storedUser.username, userId });
    } else {
      res
        .status(401)
        .json({ ok: false, error: "Invalid username or password" });
    }
  } catch (_) {
    res.status(401).json({ ok: false, error: "Invalid username or password" });
  }
});

app.get("/auth/logout", verifyAuth, (req, res) => {
  res.clearCookie("auth_token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });
  res.json({ ok: true, message: "Logged out" });
});

app.get("/session", verifyAuth, (req, res) => {
  res.json({
    ok: true,
    userId: req.user.userId,
    username: req.user.username,
  });
});

app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: UI_PATH });
});

app.listen(3000, () => {
  console.log("Port 3000");
});

export default app;
