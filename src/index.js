import express from "express";
import dotenv from "dotenv";
import { Readable } from "stream";

dotenv.config();

const app = express();
app.use(express.json({ limit: "50mb" }));

const BOT_TOKEN = process.env.BOT_TOKEN;
const PROJECTS_GROUP_ID = process.env.PROJECTS_GROUP_ID;
const GETTERS_GROUP_ID = process.env.GETTERS_GROUP_ID;
const USERS_GROUP_ID = process.env.USERS_GROUP_ID;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

async function uploadToTelegram(chatId, buffer, filename) {
  const formData = new FormData();
  formData.append("chat_id", chatId);
  formData.append("document", new Blob([buffer]), filename);

  const response = await fetch(`${TELEGRAM_API}/sendDocument`, {
    method: "POST",
    body: formData,
  });

  const result = await response.json();
  if (!result.ok) throw new Error(result.description);
  return result.result.message_id;
}

app.get("/", (req, res) => {
  res.send(`
    <h1>Dash Server</h1>
  `);
});

// Projects

app.post("/save-project", async (req, res) => {
  try {
    const { fileBase64, name } = req.body;
    const buffer = Buffer.from(fileBase64, "base64");
    const messageId = await uploadToTelegram(
      PROJECTS_GROUP_ID,
      buffer,
      `${name || "project"}.dbp.zip`,
    );
    res.json({ ok: true, projectId: messageId });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/get-project/:id", async (req, res) => {
  try {
    const messageId = req.params.id;
    const forwardRes = await fetch(`${TELEGRAM_API}/forwardMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: GETTERS_GROUP_ID,
        from_chat_id: PROJECTS_GROUP_ID,
        message_id: messageId,
      }),
    });
    const forwardData = await forwardRes.json();
    if (!forwardData.ok) throw new Error("Failed to fetch project");
    const fileId = forwardData.result.document.file_id;
    const filePathRes = await fetch(
      `${TELEGRAM_API}/getFile?file_id=${fileId}`,
    );
    const filePathData = await filePathRes.json();
    const downloadUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${filePathData.result.file_path}`;
    const fileRes = await fetch(downloadUrl);
    if (!fileRes.ok) throw new Error("Failed to download file");

    res.setHeader("Content-Type", "application/zip");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${messageId}.dbp.zip"`,
    );
    Readable.fromWeb(fileRes.body).pipe(res.status(200));
  } catch (err) {
    res.status(404).json({ ok: false, error: "Project not found or expired" });
  }
});

// Auth

/* app.post("/auth/register", async (req, res) => {
  try {
    const userData = Buffer.from(JSON.stringify(req.body));
    const userId = await uploadToTelegram(
      USER_GROUP_ID,
      userData,
      "user_meta.json",
    );

    res.json({ ok: true, userId });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message,
    });
  }
}); */

app.listen(3000, () => {
  console.log("Port 3000");
});

export default app;
