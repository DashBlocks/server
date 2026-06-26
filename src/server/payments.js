import app from "../app.js";
import * as vars from "./vars";
import { getUserIndexData, securityCheck, verifyAuth } from "./helpers.js";
import * as storage from "./storage.js";

app.post("/payments/create", verifyAuth, securityCheck, async (req, res) => {
	const { amount, currency } = req.body;
	if (!amount || !currency)
		return res.status(400).json({ success: false, message: "Amount and currency are required" });
	if (typeof amount !== "number" || amount <= 0)
		return res.status(400).json({ success: false, message: "Amount must be a positive number" });
	if (typeof currency !== "string" || currency.length !== 3)
		return res.status(400).json({ success: false, message: "Currency must be a 3-letter string" });
	const userId = req.user.userId;

	try {
		const response = await fetch("https://api.lava.top/v1/invoice/create", {
			method: "POST",
			headers: {
				"Accept": "application/json",
				"Content-Type": "application/json",
				"Authorization": vars.LAVA_API_KEY
			},
			body: JSON.stringify({
				amount,
				currency,
				order_id: userId,
				description: "Subscription for additional privileges in Dash community.",
				success_url: "https://dashblocks.org/payment-success",
				fail_url: "https://dashblocks.org/payment-fail"
			})
		});

		const data = await response.json();
		if (data && data.url) {
			res.json({ ok: true, url: data.url }); 
		} else {
			res.status(400).json({ ok: false, message: "Failed to get payment link" });
		}

	} catch (_) {
		res.status(500).json({ ok: false, message: "Failed :((" });
	}
});

app.post("/payments/lava", async (req, res) => {
	const webhookData = req.body;
	const requestKey = req.headers["authorization"] || req.headers["x-api-key"];

	if (requestKey !== vars.LAVA_API_KEY)
		return res.status(401).send({ ok: false, error: "Unauthorized" });

	const eventType = webhookData.event;
	const paymentStatus = webhookData.status;
	const userId = webhookData.order_id;
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
