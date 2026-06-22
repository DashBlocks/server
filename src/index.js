import app from "./app.js";
import "./server/auth.js";
import "./server/projects.js";
import "./server/featured-projects.js";
import "./server/users.js";
import "./server/admin.js";

// eslint-disable-next-line no-console
app.listen(process.env.PORT, "127.0.0.1", () => console.log(`Port ${process.env.PORT}`));
