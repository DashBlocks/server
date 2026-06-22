import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET;

const ASSETS_PATH = path.join(__dirname, "../assets");

const DATA_PATH = "/var/lib/dash";
const DATA_INDEX_PATH = path.join(DATA_PATH, "index.json");
const DATA_USERS_PATH = path.join(DATA_PATH, "users");
const DATA_PROJECTS_PATH = path.join(DATA_PATH, "projects");

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
	JWT_SECRET,

	ASSETS_PATH,

	DATA_PATH,
	DATA_INDEX_PATH,
	DATA_USERS_PATH,
	DATA_PROJECTS_PATH,

	FORBIDDEN_USERNAMES
};
