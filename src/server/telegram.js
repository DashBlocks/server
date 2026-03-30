import * as vars from "./vars.js";

async function uploadToTelegram(chatId, buffer, filename, caption = "") {
	try {
		const formData = new FormData();
		formData.append("chat_id", chatId);
		formData.append("document", new Blob([buffer]), filename);
		if (caption) formData.append("caption", caption);

		const response = await fetch(`${vars.TELEGRAM_API}/sendDocument`, {
			method: "POST",
			body: formData
		});

		const result = await response.json();
		if (!result.ok) return null;
		return result.result.message_id;
	} catch (_) {
		return null;
	}
}

async function editUserFile(messageId, buffer, filename) {
	try {
		const formData = new FormData();
		formData.append("chat_id", vars.USERS_GROUP_ID);
		formData.append("message_id", messageId);
		formData.append("media", JSON.stringify({
			type: "document",
			media: "attach://document"
		}));
		formData.append("document", new Blob([buffer]), filename);

		const response = await fetch(`${vars.TELEGRAM_API}/editMessageMedia`, {
			method: "POST",
			body: formData
		});

		const result = await response.json();
		return result.ok;
	} catch (_) {
		return false;
	}
}

async function fetchFromTelegram(messageId, fromChatId) {
	const forwardRes = await fetch(`${vars.TELEGRAM_API}/forwardMessage`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			chat_id: vars.GETTERS_GROUP_ID,
			from_chat_id: fromChatId,
			message_id: messageId
		})
	});
	const forwardData = await forwardRes.json();
	if (!forwardData.ok) return null;
	const fileId = forwardData.result.document.file_id;

	const filePathRes = await fetch(`${vars.TELEGRAM_API}/getFile?file_id=${fileId}`);
	const filePathData = await filePathRes.json();
	return `https://api.telegram.org/file/bot${vars.BOT_TOKEN}/${filePathData.result.file_path}`;
}

async function getLatestUsersIndex() {
	try {
		const chatRes = await fetch(
			`${vars.TELEGRAM_API}/getChat?chat_id=${vars.USERS_INDEX_GROUP_ID}`
		);
		const chatData = await chatRes.json();
		if (!chatData.ok) return null;

		const pinnedId = chatData.result?.pinned_message?.message_id;
		if (!pinnedId) return { users: {}, bannedIps: [] };

		const downloadUrl = await fetchFromTelegram(pinnedId, vars.USERS_INDEX_GROUP_ID);
		if (!downloadUrl) return { users: {}, bannedIps: [] };

		const fileRes = await fetch(downloadUrl);
		const data = await fileRes.json();

		return {
			users: data.users || {},
			bannedIps: data.bannedIps || [],
			featuredProjects: data.featuredProjects || []
		};
	} catch (_) {
		return null;
	}
}

async function updateUsersIndex(indexData) {
	const msgId = await uploadToTelegram(
		vars.USERS_INDEX_GROUP_ID,
		Buffer.from(JSON.stringify(indexData)),
		vars.INDEX_FILENAME
	);
	if (!msgId) return false;

	const pinReq = await fetch(`${vars.TELEGRAM_API}/pinChatMessage`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			chat_id: vars.USERS_INDEX_GROUP_ID,
			message_id: msgId,
			disable_notification: true
		})
	});
	const pinData = await pinReq.json();
	return pinData.ok;
}

export {
	uploadToTelegram,
	editUserFile,
	fetchFromTelegram,
	getLatestUsersIndex,
	updateUsersIndex
};
