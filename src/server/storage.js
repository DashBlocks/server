import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import * as vars from "./vars.js";

const readJson = async (filePath) => {
	const content = await fsPromises.readFile(filePath, "utf8");
	return JSON.parse(content);
};

const writeJson = async (filePath, data) =>
	fsPromises.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");

async function getIndex() {
	return await readJson(vars.DATA_INDEX_PATH);
}

async function updateIndex(indexData) {
	await writeJson(vars.DATA_INDEX_PATH, indexData);
	return true;
}

async function createUserJson(userId, userData) {
	const userDir = path.join(vars.DATA_USERS_PATH, String(userId));
	await fsPromises.mkdir(userDir, { recursive: true });
	await writeJson(path.join(userDir, `${userId}.json`), userData);
	return String(userId);
}

async function readUserJson(userId) {
	const userDir = path.join(vars.DATA_USERS_PATH, String(userId));
	return readJson(path.join(userDir, `${userId}.json`));
}

async function updateUserJson(userId, userData) {
	const userDir = path.join(vars.DATA_USERS_PATH, String(userId));
	await fsPromises.mkdir(userDir, { recursive: true });
	return writeJson(path.join(userDir, `${userId}.json`), userData);
}

async function deleteUserJson(userId) {
	try {
		const userDir = path.join(vars.DATA_USERS_PATH, String(userId));
		await fsPromises.unlink(path.join(userDir, `${userId}.json`));
	} catch (_) {
		// ignore
	}
}

async function saveProjectFile(projectId, buffer) {
	const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(projectId));
	await fsPromises.mkdir(projectDir, { recursive: true });
	return fsPromises.writeFile(path.join(projectDir, `${projectId}.zip`), buffer);
}

function streamProjectFile(projectId) {
	const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(projectId));
	return fs.createReadStream(path.join(projectDir, `${projectId}.zip`));
}

async function deleteProjectFile(projectId) {
	try {
		const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(projectId));
		await fsPromises.unlink(path.join(projectDir, `${projectId}.zip`));
	} catch (_) {
		// ignore
	}
}

async function projectFileExists(projectId) {
	try {
		const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(projectId));
		await fsPromises.access(path.join(projectDir, `${projectId}.zip`));
		return true;
	} catch (_) {
		return false;
	}
}

async function getProjectStats(projectId) {
	const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(projectId));
	const stats = await fsPromises.stat(path.join(projectDir, `${projectId}.zip`));
	return stats;
}

async function saveAvatarFile(avatarId, buffer) {
	const userDir = path.join(vars.DATA_USERS_PATH, String(avatarId));
	await fsPromises.mkdir(userDir, { recursive: true });
	return fsPromises.writeFile(path.join(userDir, `${avatarId}.png`), buffer);
}

async function saveThumbnailFile(thumbnailId, buffer) {
	const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(thumbnailId));
	await fsPromises.mkdir(projectDir, { recursive: true });
	return fsPromises.writeFile(path.join(projectDir, `${thumbnailId}.png`), buffer);
}

async function deleteThumbnailFile(thumbnailId) {
	try {
		const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(thumbnailId));
		await fsPromises.unlink(path.join(projectDir, `${thumbnailId}.png`));
	} catch (_) {
		// ignore
	}
}

async function avatarFileExists(avatarId) {
	try {
		const userDir = path.join(vars.DATA_USERS_PATH, String(avatarId));
		await fsPromises.access(path.join(userDir, `${avatarId}.png`));
		return true;
	} catch (_) {
		return false;
	}
}

async function thumbnailFileExists(thumbnailId) {
	try {
		const projectDir = path.join(vars.DATA_PROJECTS_PATH, String(thumbnailId));
		await fsPromises.access(path.join(projectDir, `${thumbnailId}.png`));
		return true;
	} catch (_) {
		return false;
	}
}

function findUserById(index, userId) {
	return Object.values(index.users).find((user) => String(user.id) === String(userId));
}

function findProjectById(index, projectId) {
	for (const author of Object.values(index.users)) {
		const project = (author.projects || []).find((entry) => String(entry.id) === String(projectId));
		if (project) return project;
	}
	return null;
}

export {
	getIndex,
	updateIndex,
	createUserJson,
	readUserJson,
	updateUserJson,
	deleteUserJson,
	saveProjectFile,
	streamProjectFile,
	deleteProjectFile,
	projectFileExists,
	getProjectStats,
	saveAvatarFile,
	saveThumbnailFile,
	deleteThumbnailFile,
	avatarFileExists,
	thumbnailFileExists,
	findUserById,
	findProjectById
};
