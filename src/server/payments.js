import app from "../app.js";
import * as vars from "./vars.js";
import { getUserIndexData, securityCheck, verifyAuth } from "./helpers.js";
import * as storage from "./storage.js";

app.post("/payments/create", verifyAuth, securityCheck, async (req, res) => {
	const { offerId, currency } = req.body;
	if (!offerId || !currency)
		return res.status(400).json({ ok: false, message: "Offer ID and currency are required" });
	if (typeof currency !== "string" || currency.length !== 3)
		return res.status(400).json({ ok: false, message: "Currency must be a 3-letter string" });
	const userId = req.user.userId;
	if (!userId) return res.status(400).json({ ok: false, message: "User ID not found" });
	const fakeEmail = userId + "@dashblocks.org"; // Lava requires an email, but we don't have one, so we use a fake one

	try {
		const response = await fetch("https://gate.lava.top/api/v3/invoice", {
			method: "POST",
			headers: {
				"Accept": "application/json",
				"Content-Type": "application/json",
				"Authorization": vars.LAVA_API_KEY
			},
			body: JSON.stringify({
				offerId,
				currency,
				email: fakeEmail,
				description: "Subscription for additional privileges in Dash community."
			})
		});

		if (!response.ok) {
			return res.status(400).json({ ok: false, message: "Failed to get payment link" });
		}

		const data = await response.json();
		if (data && data.paymentUrl) {
			return res.json({ ok: true, paymentUrl: data.paymentUrl }); 
		} else {
			return res.status(400).json({ ok: false, message: "Failed to get payment link" });
		}
	} catch (_) {
		res.status(500).json({ ok: false, message: "Failed to create payment" });
	}
});

app.post("/payments/lava", async (req, res) => {
	const webhookData = req.body;
	const requestKey = req.headers["authorization"] || req.headers["x-api-key"];

	if (requestKey !== vars.LAVA_API_KEY)
		return res.status(401).send({ ok: false, error: "Unauthorized" });

	const eventType = webhookData.event;
	const paymentStatus = webhookData.status;
	const userId = Number(webhookData.email?.split("@")[0]); // Extract userId from the fake email
	if (!userId || isNaN(userId)) return res.status(200).json({ ok: true, error: "ok" });
	const index = await storage.getIndex();
	const user = getUserIndexData(index, userId);
	if (!user || user.role === "dashteam") return res.status(200).json({ ok: true, message: "ok" });

	if (eventType === "payment_result") {
		if (paymentStatus === "success") {
			const endDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
			user.role = "dash-supporter";
			user.subscription = {
				status: "active",
				startDate: new Date().toISOString(),
				endDate
			};
			user.messages = [
				{
					type: "promoted",
					role: "dash-supporter",
					endDate,
					date: new Date().toISOString()
				},
				...(user.messages || [])
			];
			await storage.updateIndex(index);
		} else {
			if (user.role === "dash-supporter") user.role = "dasher+";
			user.subscription = {
				status: "expired",
				startDate: null,
				endDate: null
			};
			await storage.updateIndex(index);
		}
	} else if (eventType === "recurrent_payment") {
		if (paymentStatus === "success") {
			const endDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
			user.role = "dash-supporter";
			if (!user.subscription || user.subscription.status !== "active") {
				user.messages = [
					{
						type: "promoted",
						role: "dash-supporter",
						endDate,
						date: new Date().toISOString()
					},
					...(user.messages || [])
				];
			} else {
				user.messages = [
					{
						type: "subscription-recurred",
						endDate,
						date: new Date().toISOString()
					},
					...(user.messages || [])
				];
			}
			user.subscription = {
				status: "active",
				startDate: new Date().toISOString(),
				endDate
			};
			await storage.updateIndex(index);
		} else {
			if (user.role === "dash-supporter") user.role = "dasher+";
			user.subscription = {
				status: "expired",
				startDate: null,
				endDate: null
			};
			user.messages = [
				{
					type: "subscription-failed",
					date: new Date().toISOString()
				},
				...(user.messages || [])
			];
			await storage.updateIndex(index);
		}
	}

	res.status(200).json({ ok: true, message: "yay" });
});
