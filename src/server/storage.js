import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import * as vars from "./vars.js";

let indexWriteQueue = Promise.resolve();

const readJson = async (filePath) => {
	const content = await fsPromises.readFile(filePath, "utf8");
	return JSON.parse(content);
};

const writeJson = async (filePath, data) =>
	fsPromises.writeFile(filePath, JSON.stringify(data), "utf8");

async function writeIndexAtomically(indexData) {
	const serialized = JSON.stringify(indexData);
	const tempPath = path.join(
		vars.DATA_PATH,
		`.index.json.${process.pid}.${Date.now()}.tmp`
	);

	try {
		await fsPromises.writeFile(tempPath, serialized, "utf8");
		await fsPromises.rename(tempPath, vars.DATA_INDEX_PATH);
	} catch (error) {
		try {
			await fsPromises.unlink(tempPath);
		} catch (_) {/* ignore */}
		throw error;
	}
}

async function getIndex() {
	return await readJson(vars.DATA_INDEX_PATH);
}

async function updateIndex(indexData) {
	const write = indexWriteQueue.then(async () => {
		const current = await getIndex();
		indexData.commentsEnabled = current.commentsEnabled !== false;
		const projects = new Map();
		for (const user of Object.values(current.users)) {
			for (const project of user.projects || []) projects.set(String(project.id), project);
		}
		for (const user of Object.values(indexData.users)) {
			const savedUser = current.users[user.username.toLowerCase()];
			if (savedUser && String(savedUser.id) === String(user.id))
				user.lastCommentAt = savedUser.lastCommentAt || 0;
			for (const project of user.projects || []) {
				const saved = projects.get(String(project.id));
				if (!saved) continue;
				project.collaborators = structuredClone(saved.collaborators || []);
				project.collaborationRevision = saved.collaborationRevision || 0;
				project.comments = structuredClone(saved.comments || []);
				project.nextCommentId = saved.nextCommentId || (saved.comments?.at(-1)?.id || 0) + 1;
			}
		}
		await writeIndexAtomically(indexData);
	});
	indexWriteQueue = write.catch(() => {});
	await write;
	return true;
}

async function mutateIndex(mutate) {
	const write = indexWriteQueue.then(async () => {
		const index = await getIndex();
		const result = await mutate(index);
		await writeIndexAtomically(index);
		return result;
	});
	indexWriteQueue = write.catch(() => {});
	return await write;
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

async function createStudioDirectory(studioId) {
	const studioDir = path.join(vars.DATA_STUDIOS_PATH, String(studioId));
	await fsPromises.mkdir(studioDir, { recursive: true });
	return studioDir;
}

async function deleteStudioDirectory(studioId) {
	try {
		const studioDir = path.join(vars.DATA_STUDIOS_PATH, String(studioId));
		await fsPromises.rm(studioDir, { recursive: true, force: true });
	} catch (_) {
		// ignore
	}
}

async function saveStudioThumbnailFile(studioId, buffer) {
	const studioDir = await createStudioDirectory(studioId);
	return fsPromises.writeFile(path.join(studioDir, `${studioId}.png`), buffer);
}

async function studioThumbnailFileExists(studioId) {
	try {
		const studioDir = path.join(vars.DATA_STUDIOS_PATH, String(studioId));
		await fsPromises.access(path.join(studioDir, `${studioId}.png`));
		return true;
	} catch (_) {
		return false;
	}
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

function findProjectById(index, projectId) {
	for (const author of Object.values(index.users)) {
		const project = (author.projects || []).find((entry) => String(entry.id) === String(projectId));
		if (project) return project;
	}
	return null;
}

export {
	writeJson,
	readJson,
	getIndex,
	updateIndex,
	mutateIndex,
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
	createStudioDirectory,
	deleteStudioDirectory,
	saveStudioThumbnailFile,
	studioThumbnailFileExists,
	deleteThumbnailFile,
	avatarFileExists,
	thumbnailFileExists,
	findProjectById
};
