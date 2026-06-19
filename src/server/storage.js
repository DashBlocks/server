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
	const index = await readJson(vars.DATA_INDEX_PATH);
	return index;
}

async function updateIndex(indexData) {
	await writeJson(vars.DATA_INDEX_PATH, indexData);
	return true;
}

async function createUserJson(userId, userData) {
	await writeJson(path.join(vars.DATA_USERS_PATH, `${userId}.json`), userData);
	return String(userId);
}

async function readUserJson(userId) {
	return readJson(path.join(vars.DATA_USERS_PATH, `${userId}.json`));
}

async function updateUserJson(userId, userData) {
	return writeJson(path.join(vars.DATA_USERS_PATH, `${userId}.json`), userData);
}

async function deleteUserJson(userId) {
	try {
		await fsPromises.unlink(path.join(vars.DATA_USERS_PATH, `${userId}.json`));
	} catch (_) {
		// ignore
	}
}

async function saveProjectFile(projectId, buffer) {
	return fsPromises.writeFile(path.join(vars.DATA_PROJECTS_PATH, `${projectId}.dbp.zip`), buffer);
}

function streamProjectFile(projectId) {
	return fs.createReadStream(path.join(vars.DATA_PROJECTS_PATH, `${projectId}.dbp.zip`));
}

async function deleteProjectFile(projectId) {
	try {
		await fsPromises.unlink(path.join(vars.DATA_PROJECTS_PATH, `${projectId}.dbp.zip`));
	} catch (_) {
		// ignore
	}
}

async function projectFileExists(projectId) {
	try {
		await fsPromises.access(path.join(vars.DATA_PROJECTS_PATH, `${projectId}.dbp.zip`));
		return true;
	} catch (_) {
		return false;
	}
}

async function getProjectStats(projectId) {
	const stats = await fsPromises.stat(path.join(vars.DATA_PROJECTS_PATH, `${projectId}.dbp.zip`));
	return stats;
}

async function saveAvatarFile(avatarId, buffer) {
	return fsPromises.writeFile(path.join(vars.DATA_AVATARS_PATH, `${avatarId}.png`), buffer);
}

async function saveThumbnailFile(thumbnailId, buffer) {
	return fsPromises.writeFile(path.join(vars.DATA_THUMBNAILS_PATH, `${thumbnailId}.png`), buffer);
}

async function deleteThumbnailFile(thumbnailId) {
	try {
		await fsPromises.unlink(path.join(vars.DATA_THUMBNAILS_PATH, `${thumbnailId}.png`));
	} catch (_) {
		// ignore
	}
}

async function avatarFileExists(avatarId) {
	try {
		await fsPromises.access(path.join(vars.DATA_AVATARS_PATH, `${avatarId}.png`));
		return true;
	} catch (_) {
		return false;
	}
}

async function thumbnailFileExists(thumbnailId) {
	try {
		await fsPromises.access(path.join(vars.DATA_THUMBNAILS_PATH, `${thumbnailId}.png`));
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
