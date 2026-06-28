import app from "../app.js";
import * as vars from "./vars.js";
import { getUserIndexData, securityCheck, verifyAuth } from "./helpers.js";
import * as storage from "./storage.js";

app.post("/payments/create", verifyAuth, securityCheck, async (req, res) => {
	const { offerId, currency, method } = req.body;
	if (!offerId || !currency)
		return res.status(400).json({ ok: false, error: "Offer ID and currency are required" });
	if (typeof currency !== "string" || currency.length !== 3)
		return res.status(400).json({ ok: false, error: "Currency must be a 3-letter string" });
	const userId = req.user.userId;
	if (!userId) return res.status(400).json({ ok: false, error: "User ID not found" });

	// We don't store emails in users' accounts, so to idenify user we fake email with user's ID
	const fakeEmail = `${userId}@dashblocks.org`; 

	const body = {
		offerId,
		currency: currency.toUpperCase(),
		email: fakeEmail,
		promoCode: "NEW50"
	};

	if (method) {
		switch (method) {
		case "SBP": {
			body.paymentMethod = "SBP";
			break;
		}
		case "CARD": {
			body.paymentMethod = "CARD";
			break;
		}
		default:
			return res.status(400).json({ ok: false, message: "Invalid payment method" });
		}
	}

	try {
		let response = await fetch("https://gate.lava.top/api/v3/invoice", {
			method: "POST",
			headers: {
				"Accept": "application/json",
				"Content-Type": "application/json",
				"X-Api-Key": vars.LAVA_API_KEY
			},
			body: JSON.stringify(body)
		});

		if (!response.ok) {
			delete body.promoCode;
			response = await fetch("https://gate.lava.top/api/v3/invoice", {
				method: "POST",
				headers: {
					"Accept": "application/json",
					"Content-Type": "application/json",
					"X-Api-Key": vars.LAVA_API_KEY
				},
				body: JSON.stringify(body)
			});
			if (!response.ok)
				return res.status(400).json({ ok: false, error: "Failed to get payment link" });
		}

		const data = await response.json();
		if (data && data.paymentUrl)
			return res.status(200).json({ ok: true, paymentUrl: data.paymentUrl }); 
		else
			return res.status(400).json({ ok: false, error: "Failed to get payment link" });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Failed to create payment" });
	}
});

app.post("/payments/lava", async (req, res) => {
	try {
		const webhookData = req.body;
		const requestKey = req.headers["authorization"] || req.headers["x-api-key"];

		if (requestKey !== vars.LAVA_API_KEY)
			return res.status(401).json({ ok: false, error: "Unauthorized" });

		const eventType = webhookData.eventType;
		const paymentStatus = webhookData.status;

		if (eventType !== "payment.success" || paymentStatus !== "completed")
			return res.status(200).json({ ok: true, message: "ok" });

		const paidOfferId = webhookData.product?.id;
		const buyerEmail = webhookData.buyer?.email;

		const userId = buyerEmail ? Number(buyerEmail.split("@")[0]) : null;
		if (!userId || isNaN(userId)) {
			return res.status(200).json({ ok: false, error: "User ID not found or invalid" });
		}
		
		const index = await storage.getIndex();
		const user = getUserIndexData(index, userId);
		
		if (!user || user.role === "dashteam") {
			return res.status(200).json({ ok: false, error: "User not found / User's role is Dash Team" });
		}

		const daysToGive = vars.PLANS_DAYS[paidOfferId] || 30; 
		const now = Date.now();
		let baseTime = now;

		if (user.subscription && user.subscription.status === "active" && user.subscription.endDate) {
			const currentEndDate = new Date(user.subscription.endDate).getTime();
			if (currentEndDate > now) {
				baseTime = currentEndDate; 
			}
		}

		const endDate = new Date(baseTime + daysToGive * 24 * 60 * 60 * 1000).toISOString();

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

		res.status(200).json({ ok: true, message: "yay" });
	} catch (_) {
		res.status(500).json({ ok: false, error: "Something went wrong :(" });
	}
});
