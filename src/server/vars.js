import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET;
const LAVA_API_KEY = process.env.LAVA_API_KEY;

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
	"set-gradient",
	"set-recommended-project",
	"add-link",
	"update-link",
	"remove-link"
];

const PLANS_DAYS = {
	[process.env.OFFER_ID_30_DAYS]: 30,
	[process.env.OFFER_ID_90_DAYS]: 90,
	[process.env.OFFER_ID_180_DAYS]: 180,
	[process.env.OFFER_ID_360_DAYS]: 360
};

export {
	JWT_SECRET,
	LAVA_API_KEY,

	ASSETS_PATH,

	DATA_PATH,
	DATA_INDEX_PATH,
	DATA_USERS_PATH,
	DATA_PROJECTS_PATH,

	FORBIDDEN_USERNAMES,

	PLANS_DAYS
};
