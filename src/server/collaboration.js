import express from "express";
import { randomUUID, createHash } from "node:crypto";
import JSZip from "jszip";
import jwt from "jsonwebtoken";
import fs from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { WebSocket, WebSocketServer } from "ws";
import * as Y from "yjs";

import app from "../app.js";
import * as vars from "./vars.js";
import {
	roleEqualOrHigherThan,
	validateId,
	securityCheck,
	verifyAuth,
	generateUserObject
} from "./helpers.js";
import * as storage from "./storage.js";

const collaborationRooms = new Map();
let collaborationImportQueue = Promise.resolve();
let collaborationAssetUploads = 0;

class CollaborationError extends Error {
	constructor(status, message) {
		super(message);
		this.status = status;
	}
}

export const resolveProjectAccess = (index, projectId, userId) => {
	const user = Object.values(index.users).find((entry) => String(entry.id) === String(userId));
	if (!user) throw new CollaborationError(401, "Account not found");
	if (user.banned) throw new CollaborationError(403, "Account banned");

	const owner = Object.values(index.users).find((entry) =>
		(entry.projects || []).some((project) => String(project.id) === String(projectId))
	);
	if (!owner) throw new CollaborationError(404, "Project not found");

	const project = (owner.projects || []).find((entry) => String(entry.id) === String(projectId));
	if (!project) throw new CollaborationError(404, "Project not found");
	if (owner.banned) throw new CollaborationError(403, "Project owner is banned");

	const collaborators = project.collaborators || [];

	const seen = new Set();
	for (const member of collaborators) {
		if (!member || typeof member.userId !== "string" || !/^[1-9]\d{0,19}$/.test(member.userId) ||
			seen.has(member.userId) || !["editor", "viewer"].includes(member.role) ||
			typeof member.grantId !== "string" || !member.grantId ||
			typeof member.addedAt !== "string" || !Number.isFinite(Date.parse(member.addedAt))) {
			throw new Error("Invalid collaborator record");
		}
		seen.add(member.userId);
	}

	if (String(owner.id) === String(user.id)) {
		return {
			user,
			owner,
			project,
			collaborators,
			role: "owner",
			grantId: "owner"
		};
	}

	const position = collaborators.findIndex((member) => member.userId === String(user.id));
	if (position === -1) throw new CollaborationError(403, "Collaboration access denied");
	if (position >= (roleEqualOrHigherThan(owner.role, "dash-supporter") ? 5 : 2)) {
		throw new CollaborationError(
			403,
			"Project collaborators limit reached" +
			(
				roleEqualOrHigherThan(owner.role, "dash-supporter")
					? ""
					: " - support Dash to add more collaborators: https://dashblocks.org/support"
			)
		);
	}

	const member = collaborators[position];
	return {
		user,
		owner,
		project,
		collaborators,
		role: member.role,
		grantId: member.grantId
	};
};

export const verifyCollaborationToken = async (token, projectId) => {
	let claims;
	try {
		claims = jwt.verify(token, vars.JWT_SECRET, {
			algorithms: ["HS256"],
			audience: "dash-collaboration",
			issuer: "dash-api"
		});
	} catch (_) {
		throw new CollaborationError(401, "Invalid collaboration token");
	}

	if (claims.tokenType !== "collaboration" || claims.projectId !== String(projectId) ||
		claims.sub !== String(claims.userId)) {
		throw new CollaborationError(403, "Token does not match this project");
	}

	const access = resolveProjectAccess(await storage.getIndex(), projectId, claims.userId);
	if (access.role !== claims.role || access.grantId !== claims.grantId) {
		throw new CollaborationError(403, "Collaboration permission changed");
	}
	return access;
};

const checkOrigin = (req, res, next) => {
	if (!["https://dashblocks.org", "https://www.dashblocks.org", "http://localhost:3000"].includes(req.get("Origin"))) {
		return res.status(403).json({ ok: false, error: "who are you" });
	}
	next();
};

const formatCollaboration = (index, access) => {
	const limit = roleEqualOrHigherThan(access.owner.role, "dash-supporter") ? 5 : 2;
	return {
		ok: true,
		projectId: Number(access.project.id),
		revision: access.project.collaborationRevision || 0,
		role: access.role,
		collaboratorLimit: limit,
		owner: {
			...generateUserObject(
				Object.values(index.users).find((user) => String(user.id) === String(access.owner.id)),
				index
			)
		},
		collaborators: access.collaborators.map((member, position) => ({
			...generateUserObject(
				Object.values(index.users).find((user) => String(user.id) === member.userId),
				index
			),
			collaborationRole: member.role,
			addedAt: member.addedAt,
			active: position < limit
		}))
	};
};

app.get("/projects/:id/collaborators", verifyAuth, securityCheck, validateId, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const index = await storage.getIndex();
		res.json(formatCollaboration(index, resolveProjectAccess(index, req.params.id, req.user.userId)));
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.post("/projects/:id/collaborators", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const username = typeof req.body?.username === "string" ? req.body.username.trim() : "";
		const role = req.body?.role ?? "editor";
		if (!/^(?!\d+$)[a-zA-Z0-9_-]{3,20}$/.test(username) || !["editor", "viewer"].includes(role)) {
			throw new CollaborationError(400, "Invalid username and/or editor or viewer role");
		}

		const result = await storage.mutateIndex((index) => {
			const access = resolveProjectAccess(index, req.params.id, req.user.userId);
			if (access.role !== "owner") throw new CollaborationError(403, "Only the project owner can manage collaborators");

			const user = Object.values(index.users).find((entry) =>
				entry.username.toLowerCase() === username.toLowerCase()
			);
			if (!user || user.banned) throw new CollaborationError(404, "Active account not found");
			if (String(user.id) === String(access.owner.id)) {
				throw new CollaborationError(400, "Project owner already has access");
			}

			const existing = access.collaborators.find((member) => member.userId === String(user.id));
			if (!existing) {
				if (access.collaborators.length >= (roleEqualOrHigherThan(access.owner.role, "dash-supporter") ? 5 : 2)) {
					throw new CollaborationError(
						403,
						`This project allows up to ${roleEqualOrHigherThan(access.owner.role, "dash-supporter") ? 5 : 2} collaborators`
					);
				}
				access.collaborators.push({
					userId: String(user.id),
					role,
					grantId: randomUUID(),
					addedAt: new Date().toISOString()
				});
				access.project.collaborators = access.collaborators;
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			} else if (existing.role !== role) {
				existing.role = role;
				existing.grantId = randomUUID();
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			}
			return formatCollaboration(index, access);
		});
		res.json(result);
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.delete("/projects/:id/collaborators/:userId", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		if (!/^[1-9]\d{0,19}$/.test(req.params.userId)) throw new CollaborationError(400, "Invalid user ID");

		const result = await storage.mutateIndex((index) => {
			const access = resolveProjectAccess(index, req.params.id, req.user.userId);
			if (access.role !== "owner") throw new CollaborationError(403, "Only the project owner can manage collaborators");
			if (String(access.owner.id) === req.params.userId) {
				throw new CollaborationError(400, "Cannot remove the project owner");
			}

			const remaining = access.collaborators.filter((member) => member.userId !== req.params.userId);
			if (remaining.length !== access.collaborators.length) {
				access.project.collaborators = remaining;
				access.collaborators = remaining;
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			}
			return formatCollaboration(index, access);
		});
		res.json(result);
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.post("/projects/:id/collaboration-token", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const access = resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
		const token = jwt.sign({
			tokenType: "collaboration",
			projectId: String(access.project.id),
			userId: String(access.user.id),
			role: access.role,
			grantId: access.grantId
		}, vars.JWT_SECRET, {
			algorithm: "HS256",
			expiresIn: "2m",
			audience: "dash-collaboration",
			issuer: "dash-api",
			subject: String(access.user.id),
			jwtid: randomUUID()
		});
		res.json({ ok: true, projectId: String(access.project.id), role: access.role, token, expiresIn: 120 });
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

const createAssetMap = record => {
	const {collaborationId, name, ...content} = record;
	const asset = new Y.Map();
	asset.set("collaborationId", collaborationId);
	asset.set("name", name);
	asset.set("content", content);
	return asset;
};

const createCollaborationDocument = (project, projectId, sourceHash) => {
	if (!project || !Array.isArray(project.targets) || !project.targets.length) {
		throw new CollaborationError(400, "Project has no targets");
	}
	project = structuredClone(project);
	expandPrimitiveBlocks(project);
	const doc = new Y.Doc();
	const ids = new Set();
	doc.transact(() => {
		const meta = doc.getMap("collaboration");
		meta.set("schemaVersion", 4);
		meta.set("projectId", String(projectId));
		meta.set("sourceHash", sourceHash);
		const root = doc.getMap("project");
		for (const [key, value] of Object.entries(project)) {
			if (!["targets", "extensions", "extensionURLs"].includes(key)) root.set(key, value);
		}
		for (const id of project.extensions || []) doc.getMap("extensionIds").set(id, true);
		for (const [id, url] of Object.entries(project.extensionURLs || {})) doc.getMap("extensionURLs").set(id, url);
		const targets = doc.getMap("targets");
		const order = [];
		for (const source of project.targets) {
			if (!source || typeof source !== "object" || Array.isArray(source)) {
				throw new CollaborationError(400, "Invalid project target");
			}
			let id = source.collaborationId;
			if (typeof id !== "string" || !/^[\x21-\x7e]{1,128}$/.test(id) || ids.has(id)) id = randomUUID();
			ids.add(id);
			order.push(id);
			const target = new Y.Map();
			targets.set(id, target);
			for (const [key, value] of Object.entries(source)) {
				if (["blocks", "variables", "lists", "broadcasts", "comments", "costumes", "sounds", "currentCostume"].includes(key)) continue;
				if (key !== "collaborationId") target.set(key, value);
			}
			target.set("collaborationId", id);
			for (const key of ["costumes", "sounds"]) {
				const assets = new Y.Map();
				const assetOrder = [];
				for (const sourceAsset of source[key] || []) {
					let assetId = sourceAsset.collaborationId;
					if (typeof assetId !== "string" || !/^[\x21-\x7e]{1,128}$/.test(assetId) || assetOrder.includes(assetId)) {
						assetId = randomUUID();
					}
					assetOrder.push(assetId);
					assets.set(assetId, createAssetMap({ ...sourceAsset, collaborationId: assetId }));
				}
				target.set(key, assets);
				target.set(`${key}Order`, assetOrder);
			}
			target.set("currentCostumeId", target.get("costumesOrder")[source.currentCostume || 0] || null);
			for (const key of ["blocks", "variables", "lists", "broadcasts", "comments"]) {
				const entries = source[key] || {};
				if (typeof entries !== "object" || Array.isArray(entries)) throw new CollaborationError(400, "Invalid target data");
				const map = new Y.Map();
				target.set(key, map);
				for (const [entryId, value] of Object.entries(entries)) {
					if (key === "blocks") {
						if (!value || typeof value !== "object" || Array.isArray(value) ||
							!value.fields || typeof value.fields !== "object" || Array.isArray(value.fields) ||
							!value.inputs || typeof value.inputs !== "object" || Array.isArray(value.inputs)) {
							throw new CollaborationError(400, "Invalid block data");
						}
						const block = new Y.Map();
						for (const [property, propertyValue] of Object.entries(value)) {
							if (property === "fields" || property === "inputs") {
								const entries = new Y.Map();
								for (const [entry, entryValue] of Object.entries(propertyValue)) entries.set(entry, entryValue);
								block.set(property, entries);
							} else {
								block.set(property, propertyValue);
							}
						}
						map.set(entryId, block);
					} else {
						map.set(entryId, value);
					}
				}
			}
		}
		doc.getArray("targetOrder").insert(0, order);
		doc.getMap("targetSequence").set("ids", [...order]);
	});
	try {
		validateBlockGraph(readCollaborationProject(doc, projectId));
		if (Y.encodeStateAsUpdate(doc).length > 2 * 1024 * 1024) {
			throw new CollaborationError(413, "Project is too large for the current collaboration limit");
		}
		return doc;
	} catch (error) {
		doc.destroy();
		throw error;
	}
};
const primitiveBlockTypes = {
	4: ["math_number", "NUM"],
	5: ["math_positive_number", "NUM"],
	6: ["math_whole_number", "NUM"],
	7: ["math_integer", "NUM"],
	8: ["math_angle", "NUM"],
	9: ["colour_picker", "COLOUR"],
	10: ["text", "TEXT"],
	11: ["event_broadcast_menu", "BROADCAST_OPTION"],
	12: ["data_variable", "VARIABLE"],
	13: ["data_listcontents", "LIST"]
};

const expandPrimitiveBlocks = (project) => {
	for (const target of project.targets) {
		const blocks = target.blocks;
		if (!blocks || typeof blocks !== "object" || Array.isArray(blocks)) {
			throw new CollaborationError(400, "Invalid target blocks");
		}
		for (const [blockId, primitive] of Object.entries(blocks)) {
			if (!Array.isArray(primitive) || !Number.isInteger(primitive[0]) ||
				!primitiveBlockTypes[primitive[0]]) continue;
			const [opcode, fieldName] = primitiveBlockTypes[primitive[0]];
			blocks[blockId] = {
				opcode,
				next: null,
				parent: null,
				inputs: {},
				fields: { [fieldName]: primitive[0] >= 11
					? [primitive[1], primitive.length > 2 ? primitive[2] : null]
					: [primitive[1], null] },
				shadow: false,
				topLevel: true,
				x: primitive[3] ?? 0,
				y: primitive[4] ?? 0
			};
		}
		for (const [blockId, block] of Object.entries(blocks)) {
			if (!block || typeof block !== "object" || Array.isArray(block) ||
				!block.inputs || typeof block.inputs !== "object" || Array.isArray(block.inputs)) continue;
			for (const input of Object.values(block.inputs)) {
				if (!Array.isArray(input)) continue;
				for (let index = 1; index < input.length; index++) {
					const primitive = input[index];
					if (!Array.isArray(primitive) || !Number.isInteger(primitive[0]) ||
						!primitiveBlockTypes[primitive[0]]) continue;
					const [opcode, fieldName] = primitiveBlockTypes[primitive[0]];
					let entryId = `${blockId}:${index}`;
					let suffix = 0;
					while (Object.hasOwn(blocks, entryId)) {
						entryId = `${blockId}:${index}:${suffix}`;
						suffix += 1;
					}
					const fieldValue = primitive[0] >= 11
						? [primitive[1], primitive.length > 2 ? primitive[2] : null]
						: [primitive[1], null];
					const inputType = input[0];
					const shadow = primitive[0] < 12 &&
						((inputType === 1 && index === 1) || (inputType === 3 && index === 2));
					input[index] = entryId;
					blocks[entryId] = {
						opcode,
						next: null,
						parent: blockId,
						inputs: {},
						fields: { [fieldName]: fieldValue },
						shadow,
						topLevel: false
					};
				}
			}
		}
	}
};

const projectTargetAssets = target => {
	const value = target.toJSON();
	for (const key of ["costumes", "sounds"]) {
		const entries = target.get(key);
		const order = target.get(`${key}Order`);
		if (!(entries instanceof Y.Map) || !Array.isArray(order) ||
            new Set(order).size !== order.length || order.length > 1000 || entries.size > 1000) {
			throw new Error("Invalid collaboration assets");
		}
		const ids = order.filter(id => entries.has(id));
		const seen = new Set(ids);
		ids.push(...[...entries.keys()].filter(id => !seen.has(id)).sort());
		value[key] = ids.map(id => {
			const asset = entries.get(id);
			if (!(asset instanceof Y.Map) || asset.get("collaborationId") !== id) {
				throw new Error("Invalid collaboration asset ID");
			}
			return { ...asset.get("content"), name: asset.get("name"), collaborationId: id };
		});
		delete value[`${key}Order`];
	}
	const selected = value.costumes.findIndex(asset => asset.collaborationId === value.currentCostumeId);
	value.currentCostume = Math.max(0, selected);
	delete value.currentCostumeId;
	return value;
};

const readCollaborationProject = (
	doc,
	projectId,
	schemaVersion = 4,
	{ requireBlockMaps = true, validateGraph = true } = {}
) => {
	const allowed = ["collaboration", "project", "targets", "targetOrder"];
	if (schemaVersion >= 3) allowed.push("targetSequence");
	if (schemaVersion === 4) allowed.push("extensionIds", "extensionURLs");
	if ([...doc.share.keys()].some((key) => !allowed.includes(key))) throw new Error("Unknown collaboration root");
	const meta = doc.getMap("collaboration");
	if (meta.get("schemaVersion") !== schemaVersion || meta.get("projectId") !== String(projectId) ||
		typeof meta.get("sourceHash") !== "string" || !/^[a-f0-9]{64}$/.test(meta.get("sourceHash")) || meta.size !== 3) {
		throw new Error("Invalid collaboration metadata");
	}
	const targets = doc.getMap("targets");
	const membership = doc.getArray("targetOrder").toArray();
	let order = membership;
	if (!order.length || order.length > 1000 || order.length !== targets.size || new Set(order).size !== order.length) {
		throw new Error("Invalid target order");
	}
	if (schemaVersion >= 3) {
		const sequence = doc.getMap("targetSequence");
		const preferred = sequence.get("ids");
		if (sequence.size !== 1 || !Array.isArray(preferred) || preferred.length > 1000 ||
			new Set(preferred).size !== preferred.length || preferred.some((id) =>
			typeof id !== "string" || !/^[\x21-\x7e]{1,128}$/.test(id))) {
			throw new Error("Invalid target sequence");
		}
		const members = new Set(membership);
		order = preferred.filter((id) => members.has(id));
		const ordered = new Set(order);
		for (const id of membership) {
			if (!ordered.has(id)) {
				order.push(id);
				ordered.add(id);
			}
		}
	}
	const project = doc.getMap("project").toJSON();
	let stages = 0;
	project.targets = order.map((id) => {
		if (typeof id !== "string" || !/^[\x21-\x7e]{1,128}$/.test(id)) throw new Error("Invalid target ID");
		const target = targets.get(id);
		if (!(target instanceof Y.Map) || target.get("collaborationId") !== id) throw new Error("Invalid target record");
		for (const key of ["blocks", "variables", "lists", "broadcasts", "comments"]) {
			if (!(target.get(key) instanceof Y.Map)) throw new Error("Invalid target map");
		}
		if (requireBlockMaps) {
			for (const block of target.get("blocks").values()) {
				if (!(block instanceof Y.Map) || !(block.get("fields") instanceof Y.Map) ||
					!(block.get("inputs") instanceof Y.Map)) {
					throw new Error("Invalid block map");
				}
			}
		}
		const value = schemaVersion === 4 ? projectTargetAssets(target) : target.toJSON();
		if (typeof value.isStage !== "boolean" || typeof value.name !== "string" ||
			!Array.isArray(value.costumes) || !Array.isArray(value.sounds)) throw new Error("Invalid target properties");
		if (value.isStage) stages++;
		return value;
	});
	if (schemaVersion === 4) {
		project.extensions = [...doc.getMap("extensionIds").keys()];
		project.extensionURLs = doc.getMap("extensionURLs").toJSON();
		validateCollaborationExtensions(project);
	}
	if (stages !== 1) throw new Error("Project must contain exactly one stage");
	if (validateGraph) validateBlockGraph(project);
	return project;
};

const editableTargetScalars = new Set([
	"name", "x", "y", "size", "direction", "visible", "draggable", "rotationStyle",
	"currentCostume", "layerOrder", "tempo", "volume", "videoTransparency", "videoState",
	"textToSpeechLanguage"
]);
const editableTargetMaps = new Set(["blocks", "variables", "lists", "broadcasts", "comments"]);

const validateBlockGraph = (project) => {
	for (const target of project.targets) {
		const blocks = target.blocks;
		if (!blocks || typeof blocks !== "object" || Array.isArray(blocks)) throw new Error("Invalid blocks map");
		const parentCounts = new Map(Object.keys(blocks).map((id) => [id, 0]));
		const children = new Map(Object.keys(blocks).map((id) => [id, []]));
		const addEdge = (parentId, childId) => {
			if (childId === null) return;
			if (typeof childId !== "string" || !Object.hasOwn(blocks, childId)) throw new Error("Missing block reference");
			parentCounts.set(childId, parentCounts.get(childId) + 1);
			children.get(parentId).push(childId);
		};

		for (const [id, block] of Object.entries(blocks)) {
			if (!/^[\x21-\x7e]{1,128}$/.test(id) || !block || typeof block !== "object" || Array.isArray(block) ||
				typeof block.opcode !== "string" || !block.opcode ||
				(block.next !== null && typeof block.next !== "string") ||
				(block.parent !== null && typeof block.parent !== "string") ||
				typeof block.shadow !== "boolean" || typeof block.topLevel !== "boolean" ||
				!block.inputs || typeof block.inputs !== "object" || Array.isArray(block.inputs) ||
				!block.fields || typeof block.fields !== "object" || Array.isArray(block.fields)) {
				throw new Error("Invalid block record");
			}
			if (block.topLevel && (block.parent !== null || block.shadow ||
				!Number.isFinite(block.x) || !Number.isFinite(block.y))) throw new Error("Invalid top-level block");
			if (!block.topLevel && block.parent === null) throw new Error("Invalid block parent");
			if (block.next !== null) addEdge(id, block.next);
			for (const input of Object.values(block.inputs)) {
				if (!Array.isArray(input) || ![1, 2, 3].includes(input[0]) || input.length < 2 || input.length > 3) {
					throw new Error("Invalid block input");
				}
				for (const reference of input.slice(1)) addEdge(id, reference);
			}
		}

		for (const [id, block] of Object.entries(blocks)) {
			const count = parentCounts.get(id);
			if (count > 1 || (block.topLevel ? count !== 0 : count !== 1)) throw new Error("Invalid block ownership");
			if (!block.topLevel && !Object.hasOwn(blocks, block.parent)) throw new Error("Missing block parent");
			if (!block.topLevel && children.get(block.parent).filter((childId) => childId === id).length !== 1) {
				throw new Error("Block parent does not match its references");
			}
		}

		const pendingParents = new Map([...parentCounts].map(([id, count]) => [id, count]));
		const roots = [...pendingParents].filter(([, count]) => count === 0).map(([id]) => id);
		let visited = 0;
		while (roots.length) {
			const id = roots.pop();
			visited++;
			for (const childId of children.get(id)) {
				pendingParents.set(childId, pendingParents.get(childId) - 1);
				if (pendingParents.get(childId) === 0) roots.push(childId);
			}
		}
		if (visited !== Object.keys(blocks).length) throw new Error("Block graph contains a cycle");
	}
};

const validateCollaborationExtensions = (project) => {
	const ids = project.extensions || [];
	const urls = project.extensionURLs || {};
	if (!Array.isArray(ids) || ids.length > 300 || new Set(ids).size !== ids.length ||
		!urls || typeof urls !== "object" || Array.isArray(urls) || Object.keys(urls).length > 300) {
		throw new Error("Invalid extension metadata");
	}
	for (const id of [...ids, ...Object.keys(urls)]) {
		if (typeof id !== "string" || !/^[a-zA-Z0-9_-]{1,128}$/.test(id) ||
			["__proto__", "prototype", "constructor"].includes(id)) throw new Error("Invalid extension ID");
	}
	const core = new Set(["argument", "colour", "control", "data", "json", "console", "event", "looks",
		"math", "motion", "operator", "procedures", "sensing", "sound"]);
	for (const target of project.targets) {
		for (const block of Object.values(target.blocks)) {
			const index = block.opcode.indexOf("_");
			const id = index < 0 ? "" : block.opcode.slice(0, index).replace(/[^\w-]/g, "-");
			if (id && !core.has(id) && !ids.includes(id)) throw new Error("Block refers to a removed extension");
		}
	}
	for (const value of Object.values(urls)) {
		if (typeof value !== "string" || value.length > 4096) throw new Error("Invalid extension URL");
		if (/^dash-extension:[a-f0-9]{64}\.js$/.test(value)) continue;
		const url = new URL(value);
		if (url.protocol !== "https:" || url.username || url.password) throw new Error("Invalid extension URL");
	}
};

const validateCollaborationAssets = async (project, room) => {
	for (const value of new Set(Object.values(project.extensionURLs || {}))) {
		if (!value.startsWith("dash-extension:")) continue;
		const name = value.slice("dash-extension:".length);
		if (!/^[a-f0-9]{64}\.js$/.test(name)) throw new Error("Invalid custom extension reference");
		const stat = await fs.stat(path.join(room.assetDirectory, name));
		if (!stat.isFile() || !stat.size || stat.size > 2 * 1024 * 1024) throw new Error("Custom extension is unavailable");
	}
	for (const target of project.targets) {
		for (const key of ["costumes", "sounds"]) {
			const seen = new Set();
			if (target[key].length > 1000) throw new Error("Too many assets");
			for (const asset of target[key]) {
				if (!asset || typeof asset.collaborationId !== "string" ||
					!/^[\x21-\x7e]{1,128}$/.test(asset.collaborationId) || seen.has(asset.collaborationId) ||
					typeof asset.name !== "string" || asset.name.length > 1024 ||
					!/^[a-f0-9]{32}$/.test(asset.assetId) ||
					!(key === "costumes" ? ["svg", "png", "jpg", "jpeg", "bmp", "gif"] : ["wav", "mp3"]).includes(asset.dataFormat) ||
					asset.md5ext !== `${asset.assetId}.${asset.dataFormat}`) throw new Error("Invalid asset metadata");
				seen.add(asset.collaborationId);
				const name = asset.md5ext;
				if (!room.sourceAssets.has(name)) {
					const stat = await fs.stat(path.join(room.assetDirectory, name));
					if (!stat.isFile() || stat.size > 10 * 1024 * 1024) throw new Error("Asset is unavailable");
				}
			}
		}
	}
};

const assertAllowedCollaborationChanges = (previous, candidate) => {
	validateCollaborationExtensions(candidate);
	const previousRoot = { ...previous };
	const candidateRoot = { ...candidate };
	for (const key of ["targets", "extensions", "extensionURLs"]) {
		delete previousRoot[key];
		delete candidateRoot[key];
	}
	const removedExtensions = new Set((previous.extensions || []).filter(id => !candidate.extensions.includes(id)));
	if (removedExtensions.size && Array.isArray(previousRoot.monitors)) {
		previousRoot.monitors = previousRoot.monitors.filter(monitor =>
			!removedExtensions.has(monitor.opcode.split("_")[0]));
	}
	if (!isDeepStrictEqual(previousRoot, candidateRoot)) throw new Error("Project settings cannot be changed");
	for (const [id, url] of Object.entries(previous.extensionURLs || {})) {
		if (candidate.extensionURLs[id] !== url &&
			(candidate.extensions.includes(id) || Object.hasOwn(candidate.extensionURLs, id))) {
			throw new Error("Existing extension URL cannot be replaced");
		}
	}
	const previousStage = previous.targets.find((target) => target.isStage);
	const candidateStage = candidate.targets.find((target) => target.isStage);
	if (!candidateStage || candidateStage.collaborationId !== previousStage.collaborationId) {
		throw new Error("The stage cannot be replaced or removed");
	}
	const next = new Map(candidate.targets.map((target) => [target.collaborationId, target]));
	for (const target of previous.targets) {
		const other = next.get(target.collaborationId);
		if (!other) continue;
		if (target.isStage !== other.isStage) throw new Error("Target type cannot be changed");
		for (const key of new Set([...Object.keys(target), ...Object.keys(other)])) {
			if (["collaborationId", "isStage", "costumes", "sounds"].includes(key) ||
				editableTargetScalars.has(key) || editableTargetMaps.has(key)) continue;
			if (!isDeepStrictEqual(target[key], other[key])) throw new Error("Target property cannot be changed");
		}
	}
};

export const attachCollaborationWebSocket = (server) => {
	const wss = new WebSocketServer({ noServer: true, maxPayload: 384 * 1024, perMessageDeflate: false });
	const directory = path.join(vars.DATA_PATH, "collaboration");
	let closing = false;
	let checking = false;
	let checkedAt = 0;
	let upgradeWindow = Date.now();
	let upgrades = 0;

	const send = (ws, message) => {
		if (ws.readyState !== WebSocket.OPEN) return;
		if (ws.bufferedAmount > 8 * 1024 * 1024) return ws.close(1013, "Slow connection");
		ws.send(JSON.stringify(message), (error) => {
			if (error) ws.terminate();
		});
	};

	const presence = (room) => {
		const members = [...room.clients].filter((ws) => ws.readyState === WebSocket.OPEN).map((ws) => ({
			connectionId: ws.connectionId,
			userId: ws.userId,
			username: ws.username,
			role: ws.role
		}));
		for (const ws of room.clients) send(ws, { type: "members", members });
	};

	const saveChat = (room) => {
		const data = JSON.stringify({ version: 1, messages: room.chat });
		room.chatQueue = (room.chatQueue || Promise.resolve()).then(async () => {
			await fs.mkdir(directory, { recursive: true });
			const file = path.join(directory, `${room.id}.chat.json`);
			const temporary = `${file}.${randomUUID()}.tmp`;
			try {
				const handle = await fs.open(temporary, "wx", 0o600);
				try {
					await handle.writeFile(data);
					await handle.sync();
				} finally {
					await handle.close();
				}
				await fs.rename(temporary, file);
			} finally {
				await fs.unlink(temporary).catch(() => {});
			}
		}).catch(() => {});
		return room.chatQueue;
	};

	const scheduleChatSave = (room) => {
		if (room.chatSaveTimer) return;
		room.chatSaveTimer = setTimeout(() => {
			room.chatSaveTimer = null;
			saveChat(room);
		}, 1000);
	};

	const loadChatHistory = async (id) => {
		try {
			const data = JSON.parse(await fs.readFile(path.join(directory, `${id}.chat.json`), "utf8"));
			if (!data || data.version !== 1 || !Array.isArray(data.messages)) return [];
			return data.messages.filter((entry) => entry && typeof entry === "object" &&
				typeof entry.id === "string" && typeof entry.userId === "string" &&
				typeof entry.username === "string" && typeof entry.text === "string" &&
				entry.text.length <= 500 && Number.isFinite(entry.ts)).slice(-200);
		} catch (error) {
			if (error.code !== "ENOENT") return [];
			return [];
		}
	};

	const save = async (room, update) => {
		await fs.mkdir(directory, { recursive: true });
		const file = path.join(directory, `${room.id}.json`);
		const temporary = `${file}.${randomUUID()}.tmp`;
		let handle;
		try {
			handle = await fs.open(temporary, "wx", 0o600);
			await handle.writeFile(JSON.stringify({ version: 1, epoch: room.epoch, data: Buffer.from(update).toString("base64") }));
			await handle.sync();
			await handle.close();
			handle = null;
			await fs.rename(temporary, file);
			const folder = await fs.open(directory, "r");
			try {
				await folder.sync();
			} finally {
				await folder.close();
			}
		} finally {
			if (handle) await handle.close();
			await fs.rm(temporary, { force: true });
		}
	};

	const importExtensionSources = async (project, id) => {
		for (const [extensionId, value] of Object.entries(project.extensionURLs || {})) {
			if (typeof value !== "string" || !value.startsWith("data:")) continue;
			if (value.length > 8 * 1024 * 1024) throw new Error("Custom extension data URL is too large");
			const comma = value.indexOf(",");
			if (comma < 0) throw new Error("Invalid custom extension data URL");
			const payload = value.slice(comma + 1);
			const base64 = value.slice(0, comma).toLowerCase().endsWith(";base64");
			const decoded = decodeURIComponent(payload);
			if (base64 && !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(decoded)) {
				throw new Error("Invalid custom extension base64");
			}
			const bytes = Buffer.from(decoded, base64 ? "base64" : "utf8");
			if (!bytes.length || bytes.length > 2 * 1024 * 1024 || !Buffer.from(bytes.toString("utf8")).equals(bytes)) {
				throw new Error("Custom extension must contain between 1 byte and 2 MiB of UTF-8 JavaScript");
			}
			const name = `${createHash("sha256").update(bytes).digest("hex")}.js`;
			const folder = path.join(directory, `${id}.assets`);
			await fs.mkdir(folder, { recursive: true });
			const temporary = path.join(folder, `${name}.${randomUUID()}.tmp`);
			try {
				const handle = await fs.open(temporary, "wx", 0o600);
				try {
					await handle.writeFile(bytes);
					await handle.sync();
				} finally {
					await handle.close();
				}
				await fs.rename(temporary, path.join(folder, name));
				const directoryHandle = await fs.open(folder, "r");
				try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
			} finally {
				await fs.rm(temporary, { force: true });
			}
			project.extensionURLs[extensionId] = `dash-extension:${name}`;
		}
	};

	const load = (id) => {
		let room = collaborationRooms.get(id);
		if (room) return room;
		if (collaborationRooms.size >= 25) throw new CollaborationError(429, "Too many active rooms");
		room = { id, epoch: randomUUID(), doc: new Y.Doc(), clients: new Set(), pending: [], busy: false, loading: true, failed: false, touched: Date.now(), chat: [], chatSaveTimer: null };
		collaborationRooms.set(id, room);
		const initialize = collaborationImportQueue.then(async () => {
			const file = path.join(directory, `${id}.json`);
			room.sourcePath = path.join(directory, `${id}.source.zip`);
			let data;
			try {
				const stat = await fs.stat(file);
				if (stat.size > 3 * 1024 * 1024) throw new Error("Collaboration file too large");
				data = JSON.parse(await fs.readFile(file, "utf8"));
				if (!data || data.version !== 1 || typeof data.epoch !== "string" || typeof data.data !== "string") {
					throw new Error("Invalid collaboration file");
				}
				room.epoch = data.epoch;
				const update = Buffer.from(data.data, "base64");
				if (update.length > 2 * 1024 * 1024) throw new Error("Collaboration document too large");
				Y.applyUpdate(room.doc, update);
			} catch (error) {
				if (error.code !== "ENOENT") throw error;
			}
			if (!room.doc.getMap("collaboration").has("schemaVersion")) {
				if (Y.encodeStateAsUpdate(room.doc).length !== 2) {
					throw new CollaborationError(409, "Room contains legacy test data; migrate it before continuing");
				}
				const projectPath = path.join(vars.DATA_PROJECTS_PATH, id, `${id}.zip`);
				const stat = await fs.stat(projectPath);
				if (stat.size > 250 * 1024 * 1024) throw new CollaborationError(413, "Project archive is too large");
				await fs.mkdir(directory, { recursive: true });
				const temporary = `${room.sourcePath}.${randomUUID()}.tmp`;
				try {
					await fs.copyFile(projectPath, temporary);
					if ((await fs.stat(temporary)).size > 250 * 1024 * 1024) throw new Error("Project archive is too large");
					const archive = await fs.readFile(temporary);
					const hash = createHash("sha256").update(archive).digest("hex");
					const zip = await JSZip.loadAsync(archive);
					const entry = zip.file("project.json");
					if (!entry) throw new CollaborationError(400, "project.json not found");
					const text = await new Promise((resolve, reject) => {
						const chunks = [];
						let size = 0;
						const stream = entry.nodeStream("nodebuffer");
						stream.on("data", (chunk) => {
							size += chunk.length;
							if (size > 4 * 1024 * 1024) {
								stream.destroy();
								reject(new CollaborationError(413, "project.json is too large"));
								return;
							}
							chunks.push(chunk);
						});
						stream.on("error", reject);
						stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
					});
					const project = JSON.parse(text);
					await importExtensionSources(project, id);
					const doc = createCollaborationDocument(project, id, hash);
					room.doc.destroy();
					room.doc = doc;
					room.epoch = randomUUID();
					const handle = await fs.open(temporary, "r+");
					try {
						await handle.sync();
					} finally {
						await handle.close();
					}
					await fs.rename(temporary, room.sourcePath);
					await save(room, Y.encodeStateAsUpdate(room.doc));
				} finally {
					await fs.rm(temporary, { force: true });
				}
			}
			const schemaVersion = room.doc.getMap("collaboration").get("schemaVersion");
			if (schemaVersion === 1 || schemaVersion === 2 || schemaVersion === 3) {
				const project = readCollaborationProject(room.doc, id, schemaVersion, {
					requireBlockMaps: false,
					validateGraph: false
				});
				await importExtensionSources(project, id);
				const migrated = createCollaborationDocument(
					project,
					id,
					room.doc.getMap("collaboration").get("sourceHash")
				);
				room.doc.destroy();
				room.doc = migrated;
				room.epoch = randomUUID();
				await save(room, Y.encodeStateAsUpdate(room.doc));
			} else if (schemaVersion !== 4) {
				throw new Error("Unsupported collaboration schema");
			}
			readCollaborationProject(room.doc, id);
			room.sourceHash = room.doc.getMap("collaboration").get("sourceHash");
			if ((await fs.stat(room.sourcePath)).size > 250 * 1024 * 1024) throw new Error("Source archive too large");
			const source = await fs.readFile(room.sourcePath);
			if (createHash("sha256").update(source).digest("hex") !== room.sourceHash) throw new Error("Source archive changed");
			const sourceZip = await JSZip.loadAsync(source);
			room.sourceAssets = new Set(Object.keys(sourceZip.files).map((name) => path.posix.basename(name)));
			room.assetDirectory = path.join(directory, `${id}.assets`);
			room.assetQueue = Promise.resolve();
			room.assetUploads = 0;
			room.assetBytes = 0;
			await fs.mkdir(room.assetDirectory, { recursive: true });
			for (const name of await fs.readdir(room.assetDirectory)) {
				if (/^(?:[a-f0-9]{32}\.(?:svg|png|jpg|jpeg|bmp|gif|wav|mp3)|[a-f0-9]{64}\.js)$/.test(name)) {
					room.assetBytes += (await fs.stat(path.join(room.assetDirectory, name))).size;
				}
			}
			await validateCollaborationAssets(readCollaborationProject(room.doc, id), room);
			room.chat = await loadChatHistory(id);
		});
		collaborationImportQueue = initialize.catch(() => {});
		room.queue = initialize.catch((error) => {
			room.failed = true;
			collaborationRooms.delete(id);
			room.doc.destroy();
			throw error;
		}).finally(() => { room.loading = false; });
		return room;
	};

	app.get("/projects/:id/collaboration-source", verifyAuth, securityCheck, validateId, async (req, res) => {
		try {
			resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
			const room = load(String(req.params.id));
			await room.queue;
			if (room.failed) throw new Error("Room unavailable");
			resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
			room.touched = Date.now();
			res.set("Cache-Control", "no-store");
			res.type("application/zip");
			res.sendFile(room.sourcePath, (error) => {
				if (!error) return;
				if (res.headersSent) res.destroy(error);
				else res.status(500).json({ ok: false, error: "Could not read collaboration source" });
			});
		} catch (error) {
			res.status(error instanceof CollaborationError ? error.status : 500).json({
				ok: false,
				error: error instanceof CollaborationError ? error.message : "Collaboration source unavailable"
			});
		}
	});

	app.post("/projects/:id/collaboration-assets/:asset", verifyAuth, securityCheck, validateId, checkOrigin,
		async (req, res) => {
			let room;
			try {
				const access = resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
				if (access.role === "viewer") throw new CollaborationError(403, "Read-only collaboration");
				if (!/^(?:[a-f0-9]{32}\.(?:svg|png|jpg|jpeg|bmp|gif|wav|mp3)|[a-f0-9]{64}\.js)$/.test(req.params.asset)) {
					throw new CollaborationError(400, "Invalid asset filename");
				}
				room = load(String(req.params.id));
				await room.queue;
				if (room.assetUploads >= 2 || collaborationAssetUploads >= 8) throw new CollaborationError(429, "Too many asset uploads");
				room.assetUploads++;
				collaborationAssetUploads++;
				try {
					await new Promise((resolve, reject) => {
						express.raw({ type: "application/octet-stream", limit: req.params.asset.endsWith(".js") ? "2mb" : "10mb" })(req, res,
							(error) => error ? reject(new CollaborationError(error.status || 400, "Invalid asset upload")) : resolve());
					});
					if (!Buffer.isBuffer(req.body) || !req.body.length ||
						createHash(req.params.asset.endsWith(".js") ? "sha256" : "md5").update(req.body).digest("hex") !== req.params.asset.split(".")[0]) {
						throw new CollaborationError(400, "Asset hash does not match its filename");
					}
					if (req.params.asset.endsWith(".js") && !Buffer.from(req.body.toString("utf8")).equals(req.body)) {
						throw new CollaborationError(400, "Custom extension must be UTF-8 JavaScript");
					}
					const write = room.assetQueue.then(async () => {
						const current = resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
						if (current.role === "viewer" || current.grantId !== access.grantId) {
							throw new CollaborationError(403, "Collaboration permission changed");
						}
						await fs.mkdir(room.assetDirectory, { recursive: true });
						const file = path.join(room.assetDirectory, req.params.asset);
						try {
							await fs.access(file);
							return;
						} catch (error) {
							if (error.code !== "ENOENT") throw error;
						}
						if (room.assetBytes + req.body.length > 250 * 1024 * 1024) {
							throw new CollaborationError(413, "Collaboration asset quota reached");
						}
						const temporary = `${file}.${randomUUID()}.tmp`;
						try {
							const handle = await fs.open(temporary, "wx", 0o600);
							try {
								await handle.writeFile(req.body);
								await handle.sync();
							} finally {
								await handle.close();
							}
							await fs.rename(temporary, file);
							const folder = await fs.open(room.assetDirectory, "r");
							try { await folder.sync(); } finally { await folder.close(); }
							room.assetBytes += req.body.length;
						} finally {
							await fs.rm(temporary, { force: true });
						}
					});
					room.assetQueue = write.catch(() => {});
					await write;
					room.touched = Date.now();
					res.set("Cache-Control", "no-store").json({ ok: true });
				} finally {
					room.assetUploads--;
					collaborationAssetUploads--;
				}
			} catch (error) {
				res.status(error instanceof CollaborationError ? error.status : 500).json({
					ok: false, error: error instanceof CollaborationError ? error.message : "Asset upload failed"
				});
			}
		});

	app.get("/projects/:id/collaboration-assets/:asset", verifyAuth, securityCheck, validateId,
		async (req, res) => {
			try {
				resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
				if (!/^(?:[a-f0-9]{32}\.(?:svg|png|jpg|jpeg|bmp|gif|wav|mp3)|[a-f0-9]{64}\.js)$/.test(req.params.asset)) {
					throw new CollaborationError(400, "Invalid asset filename");
				}
				const room = load(String(req.params.id));
				await room.queue;
				resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
				room.touched = Date.now();
				res.set("Cache-Control", "no-store");
				res.set("X-Content-Type-Options", "nosniff");
				res.type("application/octet-stream");
				res.sendFile(path.join(room.assetDirectory, req.params.asset), (error) => {
					if (!error) return;
					if (res.headersSent) res.destroy(error);
					else res.status(error.code === "ENOENT" ? 404 : 500).json({ ok: false, error: "Asset unavailable" });
				});
			} catch (error) {
				res.status(error instanceof CollaborationError ? error.status : 500).json({
					ok: false, error: error instanceof CollaborationError ? error.message : "Asset unavailable"
				});
			}
		});

	const upgrade = (req, socket, head) => {
		socket.on("error", () => socket.destroy());
		if (Date.now() - upgradeWindow >= 1000) {
			upgradeWindow = Date.now();
			upgrades = 0;
		}
		const match = /^\/collaboration\/([1-9]\d{0,19})$/.exec(req.url);
		if (closing || !match || !["https://dashblocks.org", "https://www.dashblocks.org", "http://localhost:3000"].includes(req.headers.origin) ||
			++upgrades > 50 || wss.clients.size >= 100 || [...wss.clients].filter((ws) => !ws.userId).length >= 20) {
			socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
			return;
		}
		wss.handleUpgrade(req, socket, head, (ws) => {
			ws.projectId = match[1];
			ws.connectionId = randomUUID();
			ws.features = new Set();
			ws.alive = true;
			ws.windowStart = Date.now();
			ws.messages = 0;
			ws.bytes = 0;
			ws.on("error", () => ws.terminate());
			ws.on("pong", () => { ws.alive = true; });
			const timeout = setTimeout(() => ws.close(4401, "Authentication timeout"), 5000);
			ws.on("close", () => {
				clearTimeout(timeout);
				if (ws.room) {
					ws.room.clients.delete(ws);
					ws.room.pending = ws.room.pending.filter((item) => item.ws !== ws);
					ws.room.touched = Date.now();
					presence(ws.room);
				}
			});
			ws.on("message", async (raw, binary) => {
				try {
					if (Date.now() - ws.windowStart >= 1000) {
						ws.windowStart = Date.now();
						ws.messages = 0;
						ws.bytes = 0;
					}
					ws.bytes += raw.length;
					if (binary || ++ws.messages > 30 || ws.bytes > 512 * 1024) return ws.close(4429, "Message limit");
					const message = JSON.parse(raw.toString());
					if (!message || typeof message !== "object") return ws.close(4400, "Invalid message");
					if (!ws.userId) {
						if (ws.authenticating || message.type !== "auth" || typeof message.token !== "string" || message.token.length > 4096) {
							return ws.close(4400, "Authentication required");
						}
						ws.authenticating = true;
						ws.features = new Set(
							Array.isArray(message.features) ?
								message.features.filter((feature) => feature === "presence" || feature === "chat") :
								[]
						);
						const access = await verifyCollaborationToken(message.token, ws.projectId);
						if (ws.readyState !== WebSocket.OPEN || closing) return;
						const room = load(ws.projectId);
						const join = room.queue.then(async () => {
							if (ws.readyState !== WebSocket.OPEN || closing) return;
							if (room.failed) throw new Error("Room unavailable");
							const current = resolveProjectAccess(await storage.getIndex(), ws.projectId, access.user.id);
							if (ws.readyState !== WebSocket.OPEN || closing) return;
							if (current.role !== access.role || current.grantId !== access.grantId) throw new CollaborationError(403, "Permission changed");
							const userId = String(current.user.id);
							if ([...room.clients].filter((peer) => peer.userId === userId).length >= 2 ||
								[...wss.clients].filter((peer) => peer.userId === userId).length >= 6) {
								throw new CollaborationError(429, "Too many connections for this account");
							}
							ws.userId = userId;
							ws.username = current.user.username;
							ws.role = current.role;
							ws.grantId = current.grantId;
							ws.room = room;
							room.clients.add(ws);
							room.touched = Date.now();
							clearTimeout(timeout);
						send(ws, {
							type: "ready", epoch: room.epoch, userId, role: ws.role, grantId: ws.grantId,
							connectionId: ws.connectionId,
							features: ["presence", "chat"],
							data: Buffer.from(Y.encodeStateAsUpdate(room.doc)).toString("base64")
						});
						presence(room);
						if (ws.features.has("chat")) send(ws, { type: "chat-history", messages: room.chat });
						});
						room.queue = join.catch(() => {});
						await join;
						return;
					}
					if (message.type === "presence") {
						if (!message.state || typeof message.state !== "object" || Array.isArray(message.state) ||
							JSON.stringify(message.state).length > 2048) {
							return ws.close(4400, "Invalid presence");
						}
						const state = message.state;
						for (const peer of ws.room.clients) {
							if (peer !== ws && peer.features.has("presence")) {
								send(peer, {
									type: "presence",
									connectionId: ws.connectionId,
									userId: ws.userId,
									username: ws.username,
									state
								});
							}
						}
						return;
					}
					if (message.type === "chat") {
						const pin = message.pin === undefined ? null : message.pin;
						if (typeof message.text !== "string" || !message.text.trim().length || message.text.length > 500 ||
							(pin !== null && (typeof pin !== "object" || Array.isArray(pin) ||
								!["sprite", "block", "costume"].includes(pin.type) ||
								typeof pin.targetId !== "string" || !pin.targetId.length || pin.targetId.length > 64 ||
								(pin.blockId !== undefined && (typeof pin.blockId !== "string" || pin.blockId.length > 64)) ||
								(pin.name !== undefined && (typeof pin.name !== "string" || pin.name.length > 64))))) {
							return ws.close(4400, "Invalid chat message");
						}
						const entry = {
							id: randomUUID(),
							userId: ws.userId,
							username: ws.username,
							ts: Date.now(),
							text: message.text,
							pin: pin && {
								type: pin.type,
								targetId: pin.targetId,
								blockId: pin.blockId,
								name: pin.name
							}
						};
						ws.room.chat.push(entry);
						if (ws.room.chat.length > 200) ws.room.chat.splice(0, ws.room.chat.length - 200);
						for (const peer of ws.room.clients) {
							if (peer.features.has("chat")) send(peer, { type: "chat", message: entry });
						}
						scheduleChatSave(ws.room);
						return;
					}
					if (message.type !== "update" || typeof message.id !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(message.id) ||
						typeof message.data !== "string" || message.data.length > 350000 ||
						!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.data)) {
						return ws.close(4400, "Invalid update");
					}
					if (ws.role === "viewer") return ws.close(4403, "Read-only access");
					if (message.epoch !== ws.room.epoch) return ws.close(4409, "Room changed");
					if (ws.pending) return ws.close(4429, "Wait for acknowledgement");
					const update = Buffer.from(message.data, "base64");
					if (!update.length || update.length > 256 * 1024) return ws.close(4400, "Update too large");
					ws.pending = true;
					ws.room.pending.push({ ws, id: message.id, update });
				} catch (error) {
					if (error instanceof CollaborationError) ws.close(error.status === 429 ? 4429 : 4403, error.message.slice(0,100));
					else if (error instanceof SyntaxError) ws.close(4400, "Invalid JSON");
					else ws.close(1011, "Collaboration unavailable");
				}
			});
		});
	};
	server.on("upgrade", upgrade);

	const tick = setInterval(async () => {
		if (checking || closing || !wss.clients.size) return;
		if (Date.now() - checkedAt < 1000 && ![...collaborationRooms.values()].some((room) => room.pending.length)) return;
		checking = true;
		try {
			const index = await storage.getIndex();
			if (closing) return;
			checkedAt = Date.now();
			for (const ws of wss.clients) {
				if (!ws.userId || ws.readyState !== WebSocket.OPEN) continue;
				try {
					const access = resolveProjectAccess(index, ws.projectId, ws.userId);
					if (access.role !== ws.role || access.grantId !== ws.grantId) throw new Error("Permission changed");
				} catch (_) {
					ws.close(4403, "Collaboration access changed");
				}
			}
			for (const room of collaborationRooms.values()) {
				if (room.busy || !room.pending.length) continue;
				room.busy = true;
				const batch = room.pending.splice(0);
				room.queue = room.queue.then(async () => {
					let next = new Y.Doc();
					const accepted = [];
					try {
						Y.applyUpdate(next, Y.encodeStateAsUpdate(room.doc));
						for (const item of batch) {
							if (item.ws.readyState !== WebSocket.OPEN) continue;
							const candidate = new Y.Doc();
							try {
								Y.applyUpdate(candidate, Y.encodeStateAsUpdate(next));
								Y.applyUpdate(candidate, item.update);
								const previous = readCollaborationProject(next, room.id);
								const proposed = readCollaborationProject(candidate, room.id);
								assertAllowedCollaborationChanges(previous, proposed);
								await validateCollaborationAssets(proposed, room);
								validateBlockGraph(proposed);
								if (candidate.getMap("collaboration").get("sourceHash") !== room.sourceHash) {
									throw new Error("Source archive cannot be changed by a document update");
								}
								if (candidate.store.pendingStructs || candidate.store.pendingDs || Y.encodeStateAsUpdate(candidate).length > 2 * 1024 * 1024) {
									throw new Error("Invalid document");
								}
								next.destroy();
								next = candidate;
								accepted.push(item);
							} catch (_) {
								candidate.destroy();
								item.ws.close(4400, "Invalid or oversized document");
							}
						}
						if (!accepted.length) return;
						await save(room, Y.encodeStateAsUpdate(next));
						room.doc.destroy();
						room.doc = next;
						next = null;
						const data = Buffer.from(Y.mergeUpdates(accepted.map((item) => item.update))).toString("base64");
						for (const ws of room.clients) send(ws, { type: "update", data });
						for (const item of accepted) send(item.ws, { type: "ack", id: item.id });
						room.touched = Date.now();
					} catch (_) {
						room.failed = true;
						collaborationRooms.delete(room.id);
						room.doc.destroy();
						for (const ws of room.clients) ws.close(1011, "Could not save collaboration");
					} finally {
						if (next) next.destroy();
						for (const item of batch) item.ws.pending = false;
					}
				}).finally(() => { room.busy = false; });
				await room.queue;
			}
		} catch (_) {
			for (const ws of wss.clients) ws.close(1011, "Could not check collaboration access");
		} finally {
			checking = false;
		}
	}, 100);

	const heartbeat = setInterval(() => {
		for (const ws of wss.clients) {
			if (!ws.alive || ws.readyState !== WebSocket.OPEN) {
				ws.terminate();
				continue;
			}
			ws.alive = false;
			ws.ping();
		}
		for (const [id, room] of collaborationRooms) {
			if (!room.assetUploads && !room.clients.size && !room.loading && !room.busy && !room.pending.length && Date.now() - room.touched > 60000) {
				collaborationRooms.delete(id);
				room.doc.destroy();
			}
		}
	}, 15000);

	return async () => {
		closing = true;
		clearInterval(tick);
		clearInterval(heartbeat);
		server.off("upgrade", upgrade);
		for (const ws of wss.clients) ws.terminate();
		await Promise.allSettled([...collaborationRooms.values()].map(async (room) => {
			clearTimeout(room.chatSaveTimer);
			room.chatSaveTimer = null;
			await room.queue;
			await saveChat(room);
		}));
		await new Promise((resolve) => wss.close(resolve));
		for (const room of collaborationRooms.values()) room.doc.destroy();
		collaborationRooms.clear();
	};
};
