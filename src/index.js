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
import JSZip from "jszip";
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

const forbiddenUsernames = [
  "unknown",
  "admin",
  "system",
  "dashblocks",
  "dash",
  "dashteam",
];

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
  max: 15,
  message: { ok: false, error: "Too many attempts, try again later" },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { ok: false, error: "Upload limit reached, try again later" },
});

// --- Helpers ---

const isValidUsername = (username) => {
  const regex = /^[a-zA-Z0-9-_]+$/;
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
  // For development.
  url.toLowerCase().startsWith("http://localhost:");

async function uploadToTelegram(chatId, buffer, filename, caption = "") {
  try {
    const formData = new FormData();
    formData.append("chat_id", chatId);
    formData.append("document", new Blob([buffer]), filename);
    if (caption) formData.append("caption", caption);

    const response = await fetch(`${TELEGRAM_API}/sendDocument`, {
      method: "POST",
      body: formData,
    });

    const result = await response.json();
    if (!result.ok) return null;
    return result.result.message_id;
  } catch (_) {
    return null;
  }
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
  try {
    const chatRes = await fetch(
      `${TELEGRAM_API}/getChat?chat_id=${USERS_INDEX_GROUP_ID}`,
    );
    const chatData = await chatRes.json();
    if (!chatData.ok) return null;

    const pinnedId = chatData.result?.pinned_message?.message_id;
    if (!pinnedId) return { users: {}, bannedIps: [] };

    const downloadUrl = await fetchFromTelegram(pinnedId, USERS_INDEX_GROUP_ID);
    if (!downloadUrl) return { users: {}, bannedIps: [] };

    const fileRes = await fetch(downloadUrl);
    const data = await fileRes.json();

    // "Migration" for old array index
    if (Array.isArray(data.usernames)) {
      const migrated = { users: {}, bannedIps: data.bannedIps || [] };
      data.usernames.forEach((u) => {
        migrated.users[u.toLowerCase()] = { role: "dasher", banned: false };
      });
      return migrated;
    }

    return {
      users: data.users || {},
      bannedIps: data.bannedIps || [],
    };
  } catch (_) {
    return null;
  }
}

async function updateUsersIndex(indexData) {
  const msgId = await uploadToTelegram(
    USERS_INDEX_GROUP_ID,
    Buffer.from(JSON.stringify(indexData)),
    "users_index.json",
  );
  if (!msgId) return false;

  const pinReq = await fetch(`${TELEGRAM_API}/pinChatMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: USERS_INDEX_GROUP_ID,
      message_id: msgId,
      disable_notification: true,
    }),
  });
  const pinData = await pinReq.json();
  return pinData.ok;
}

// --- Middlewares ---

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
      return res.status(500).json({ ok: false, error: "Database unreachable" });

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

// --- Routes ---

app.get("/", (req, res) => res.sendFile("index.html", { root: UI_PATH }));

app.get("/register", (req, res) =>
  res.sendFile("register.html", { root: UI_PATH }),
);
app.get("/login", (req, res) => res.sendFile("login.html", { root: UI_PATH }));

app.get("/upload-project", (req, res) =>
  res.sendFile("upload-project.html", { root: UI_PATH }),
);

// --- Projects ---
app.post(
  "/save-project",
  verifyAuth,
  securityCheck,
  uploadLimiter,
  upload.single("file"),
  async (req, res) => {
    // Save project
    const { name, description } = req.body;
    const metadata = JSON.stringify({
      name: name || "Untitled",
      description: description || "",
      author: { id: Number(req.user.userId), username: req.user.username },
    });

    const file = req.file;
    if (!file)
      return res.status(400).json({ ok: false, error: "No file uploaded" });

    const zip = await JSZip.loadAsync(file.buffer);
    const projectData = await zip.file("project.json").async("string");
    const projectJson = JSON.parse(projectData);
    const hasCustomExtensions = Object.values(
      projectJson.extensionURLs || {},
    ).some(
      (ext) =>
        (ext.startsWith("http") || ext.startsWith("data")) &&
        !isTrustedUrl(ext),
    );
    if (hasCustomExtensions && req.userRole === "dasher") {
      return res
        .status(403)
        .json({ ok: false, error: "Custom extensions require Dasher+ role" });
    }

    const projectId = await uploadToTelegram(
      PROJECTS_GROUP_ID,
      file.buffer,
      `${name || "Untitled"}.dbp.zip`,
      metadata,
    );
    res.json({ ok: true, projectId });

    // Update user profile
    const index = req.usersIndex;
    const userKey = req.user.username.toLowerCase();
    const user = index.users[userKey];

    user.projects.push({
      id: projectId,
      name: name || "Untitled",
      description: description || "",
    });

    const accountAgeMs = Date.now() - new Date(user.joinedAt).getTime();

    const hasEnoughProjects = user.projects.length >= 3;
    const isOldEnough = accountAgeMs >= 14 * 24 * 60 * 60 * 1000;
    const isActive =
      new Date(user.lastActive).getTime() >
      Date.now() - 7 * 24 * 60 * 60 * 1000;

    user.lastActive = new Date().toISOString();

    if (
      user.role === "dasher" &&
      hasEnoughProjects &&
      isOldEnough &&
      isActive
    ) {
      user.role = "dasher+";
    }

    await updateUsersIndex(index);
  },
);

app.get("/get-project/:id", validateId, securityCheck, async (req, res) => {
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
  } catch (_) {
    res.status(404).json({ ok: false, error: "Project not found" });
  }
});

app.get("/projects/:id", validateId, securityCheck, async (req, res) => {
  try {
    const forwardRes = await fetch(`${TELEGRAM_API}/forwardMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: GETTERS_GROUP_ID,
        from_chat_id: PROJECTS_GROUP_ID,
        message_id: req.params.id,
      }),
    });

    const data = await forwardRes.json();
    if (!data.ok || !data.result.document)
      return res.status(404).json({ ok: false, error: "Project not found" });

    const doc = data.result.document;
    let metadata = {
      name: "Untitled",
      description: "",
      author: { id: null, username: "Unknown" },
    };

    try {
      metadata = JSON.parse(data.result.caption);
      metadata.author.id = metadata.author.id
        ? Number(metadata.author.id)
        : null;
    } catch (_) {
      // It might be old project
      const lastUnderscoreIndex = doc.file_name.lastIndexOf("_");
      if (lastUnderscoreIndex !== -1) {
        metadata.name = doc.file_name.substring(0, lastUnderscoreIndex);
        metadata.author.username = doc.file_name
          .substring(lastUnderscoreIndex + 1)
          .replace(".dbp.zip", "");
      } else if (doc.file_name.endsWith(".dbp.zip")) {
        metadata.name =
          doc.file_name.replace(".dbp.zip", "") !== ""
            ? doc.file_name.replace(".dbp.zip", "")
            : "Untitled";
      }
    }

    res.json({
      ok: true,
      project: {
        id: data.result.forward_from_message_id,
        name: metadata.name,
        description: metadata.description,
        author: metadata.author,
        fileSize: doc.file_size,
        uploadedAt: data.result.forward_date
          ? new Date(data.result.forward_date * 1000).toISOString()
          : null,
      },
    });
  } catch (_) {
    res
      .status(500)
      .json({ ok: false, error: "Failed to fetch project metadata" });
  }
});

// --- Auth ---

app.post("/auth/register", authLimiter, securityCheck, async (req, res) => {
  try {
    const { username, password } = req.body;
    const userIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    if (!isValidUsername(username))
      return res.status(400).json({
        ok: false,
        error:
          "Username must be 3-20 characters long and contain only letters, numbers, underscores, and dashes",
      });
    if (forbiddenUsernames.includes(username.toLowerCase()))
      return res
        .status(400)
        .json({ ok: false, error: "You cannot use this username" });
    if (!password || (password.length < 8 && password.length > 100))
      return res
        .status(400)
        .json({ ok: false, error: "Password must be 8-100 characters long" });

    const index = req.usersIndex;
    if (index.users[username.toLowerCase()])
      return res.status(400).json({ ok: false, error: "Username taken" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = JSON.stringify({
      username,
      password: hashedPassword,
      ip: userIp,
      banned: false,
    });

    const userId = await uploadToTelegram(
      USERS_GROUP_ID,
      Buffer.from(userData),
      `${username}.json`,
    );
    if (!userId) throw new Error("Storage failed");

    index.users[username.toLowerCase()] = {
      role: "dasher",
      banned: false,
      ip: userIp,
      projects: [],
      joinedAt: new Date().toISOString(),
      lastActive: new Date().toISOString(),
    };
    await updateUsersIndex(index);

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

app.post("/auth/login", securityCheck, async (req, res) => {
  try {
    const { userId, password } = req.body;
    const downloadUrl = await fetchFromTelegram(userId, USERS_GROUP_ID);
    const userFileRes = await fetch(downloadUrl);
    const storedUser = await userFileRes.json();

    if (await bcrypt.compare(password, storedUser.password)) {
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

app.get("/users/:id", validateId, securityCheck, async (req, res) => {
  try {
    const downloadUrl = await fetchFromTelegram(req.params.id, USERS_GROUP_ID);
    const userFileRes = await fetch(downloadUrl);
    const storedUser = await userFileRes.json();
    const indexData = req.usersIndex.users[storedUser.username.toLowerCase()];

    res.json({
      ok: true,
      user: {
        username: storedUser.username,
        role: indexData?.role || "dasher",
        joinedAt: indexData?.joinedAt,
        projects: indexData?.projects || [],
      },
    });
  } catch (e) {
    res.status(404).json({ ok: false, error: "User not found" });
  }
});

app.get("/session", verifyAuth, securityCheck, (req, res) => {
  const metadata = req.usersIndex.users[req.user.username.toLowerCase()];
  res.json({
    ok: true,
    userId: Number(req.user.userId),
    username: req.user.username,
    role: metadata?.role || "dasher",
    projects: metadata?.projects || [],
    joinedAt: metadata?.joinedAt,
    lastActive: metadata?.lastActive,
  });
});

app.get("/auth/logout", verifyAuth, securityCheck, (req, res) => {
  res.clearCookie("auth_token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
  });
  res.json({ ok: true, message: "Logged out" });
});

// --- Admin ---

app.post("/admin/manage-user", verifyAuth, securityCheck, async (req, res) => {
  if (req.userRole !== "dashteam")
    return res.status(403).json({
      ok: false,
      error: "Only Dash Team can do this, what did you expect?",
    });

  const { targetUsername, action, role } = req.body;
  const index = req.usersIndex;
  const target = index.users[targetUsername.toLowerCase()];

  if (!target)
    return res.status(404).json({ ok: false, error: "User not found" });

  if (action === "ban-user") {
    target.banned = true;
  } else if (action === "ban-ip") {
    if (target.ip && !index.bannedIps.includes(target.ip))
      index.bannedIps.push(target.ip);
  } else if (action === "unban-user") {
    target.banned = false;
  } else if (action === "unban-ip") {
    index.bannedIps = index.bannedIps.filter((ip) => ip !== target.ip);
  } else if (action === "promote" && role) {
    target.role = role;
  }

  const success = await updateUsersIndex(index);
  res.json({ ok: success });
});

// eslint-disable-next-line no-console
app.listen(3000, () => console.log("Port 3000"));

export default app;
