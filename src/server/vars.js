import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_SCRATCH_VERIFY_SECRET = process.env.JWT_SCRATCH_VERIFY_SECRET;

const UI_PATH = path.join(__dirname, "../ui");
const ASSETS_PATH = path.join(__dirname, "../assets");

const DATA_PATH = "/var/lib/dash";
const DATA_BASE_PATH = path.join(DATA_PATH, "data");
const DATA_INDEX_PATH = path.join(DATA_BASE_PATH, "index.json");
const DATA_USERS_PATH = path.join(DATA_BASE_PATH, "users");
const DATA_PROJECTS_PATH = path.join(DATA_BASE_PATH, "projects");
const DATA_ASSETS_PATH = path.join(DATA_PATH, "assets");
const DATA_AVATARS_PATH = path.join(DATA_ASSETS_PATH, "users_avatars");
const DATA_THUMBNAILS_PATH = path.join(DATA_ASSETS_PATH, "project_thumbnails");

const FORBIDDEN_USERNAMES = [
	"user",
	"unknown",
	"dashteam",
	"upload-avatar",
	"avatars",
	"set-description",
	"set-recommended-project",
	"add-link",
	"update-link",
	"remove-link"
];

export {
	SERVER_URL,

	JWT_SECRET,
	JWT_SCRATCH_VERIFY_SECRET,

	UI_PATH,
	ASSETS_PATH,

	DATA_PATH,
	DATA_BASE_PATH,
	DATA_INDEX_PATH,
	DATA_USERS_PATH,
	DATA_PROJECTS_PATH,
	DATA_ASSETS_PATH,
	DATA_AVATARS_PATH,
	DATA_THUMBNAILS_PATH,

	FORBIDDEN_USERNAMES
};
