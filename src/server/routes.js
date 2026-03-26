import app from "../index";
import { UI_PATH } from "./vars";

app.get("/", (req, res) => res.sendFile("index.html", { root: UI_PATH }));

app.get("/register", (req, res) =>
	res.sendFile("register.html", { root: UI_PATH })
);
app.get("/login", (req, res) => res.sendFile("login.html", { root: UI_PATH }));
