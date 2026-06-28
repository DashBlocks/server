import app from "./app.js";
import * as storage from "./server/storage.js";
import "./server/auth.js";
import "./server/projects.js";
import "./server/users.js";
import "./server/admin.js";
import "./server/featured-projects.js";
import "./server/payments.js";

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
								role: "user",
								date: new Date().toISOString()
							},
							...(user.messages || [])
						];
						isUpdated = true;
					}
				}
			}
			if (isUpdated) {
				await storage.updateIndex(index);
			}
		} catch (_) {/* ignore */}
	}, 1000 * 60 * 60);
}
checkSubs();

// eslint-disable-next-line no-console
app.listen(process.env.PORT, "127.0.0.1", () => console.log(`Port ${process.env.PORT}`));
