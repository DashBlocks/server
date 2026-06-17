import app from "./app.js";
import "./server/routes.js";
import "./server/auth.js";
import "./server/projects.js";
import "./server/featured-projects.js";
import "./server/users.js";
import "./server/admin.js";

// eslint-disable-next-line no-console
app.listen(3000, () => console.log("Port 3000"));
