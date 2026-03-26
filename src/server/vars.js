import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BOT_TOKEN = process.env.BOT_TOKEN;
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_VERIFY_SECRET = process.env.JWT_VERIFY_SECRET;

const UI_PATH = path.join(__dirname, "../ui");
const ASSETS_PATH = path.join(__dirname, "../assets");

const PROJECTS_GROUP_ID = process.env.PROJECTS_GROUP_ID;
const GETTERS_GROUP_ID = process.env.GETTERS_GROUP_ID;
const USERS_GROUP_ID = process.env.USERS_GROUP_ID;
const INDEX_FILENAME = "users_index.json";
const USERS_INDEX_GROUP_ID = process.env.USERS_INDEX_GROUP_ID;
const AVATARS_GROUP_ID = process.env.AVATARS_GROUP_ID;
const THUMBNAILS_GROUP_ID = process.env.THUMBNAILS_GROUP_ID;

const FORBIDDEN_USERNAMES = [
	"unknown",
	"admin",
	"dashblocks",
	"dash",
	"dashteam"
];

export {
	BOT_TOKEN,
	TELEGRAM_API,

	JWT_SECRET,
	JWT_VERIFY_SECRET,

	UI_PATH,
	ASSETS_PATH,

	PROJECTS_GROUP_ID,
	GETTERS_GROUP_ID,
	USERS_GROUP_ID,
	INDEX_FILENAME,
	USERS_INDEX_GROUP_ID,
	AVATARS_GROUP_ID,
	THUMBNAILS_GROUP_ID,

	FORBIDDEN_USERNAMES
};
