import { createServer } from "node:http";

import app from "./app.js";
import * as storage from "./server/storage.js";
import "./server/auth.js";
import "./server/projects.js";
import "./server/comments.js";
import { attachCollaborationWebSocket } from "./server/collaboration.js";
import "./server/studios.js";
import "./server/search.js";
import "./server/users.js";
import "./server/admin.js";
import "./server/featured.js";
import "./server/payments.js";

app.get("/", async (_, res) => {
	const index = await storage.getIndex();
	if (
		index && typeof index?.users === 'object' &&
		index.users !== null && !Array.isArray(index.users) &&
		Object.keys(index.users).length > 0
	) {
		return res.status(200).json({ ok: true, message: "Dash Server API seems to work fine" });
	}
	return res.status(500).json({ ok: false, message: "noo Dash server api is down" });
});

function checkSubs() {
	setInterval(async () => {
		try {
			const index = await storage.getIndex();
			let isUpdated = false;
			const now = Date.now();
			const users = Object.values(index.users);
			for (const user of users) {
				if (!user || user.role !== "dash-supporter" || !user.subscription) continue;

				if (user.subscription.status === "active" && user.subscription.endDate) {
					const endDate = new Date(user.subscription.endDate).getTime();
					if (now > endDate) {
						user.role = "dasher+";
						user.subscription = {
							status: "expired",
							startDate: null,
			                endDate: null
						};
						user.messages = [
							{
								type: "demoted",
								role: "dasher+",
								date: new Date().toISOString()
							},
							...(user.messages || [])
						];
						user.unreadMessages = (user.unreadMessages || 0) + 1;
						isUpdated = true;
					}
				}
			}
			if (isUpdated) await storage.updateIndex(index);
		} catch (_) {/* ignore */}
	}, 1000 * 60 * 60);
}
checkSubs();

const server = createServer(app);
attachCollaborationWebSocket(server);
// eslint-disable-next-line no-console
server.listen(process.env.PORT, "0.0.0.0", () => console.log(`Port ${process.env.PORT}`));
