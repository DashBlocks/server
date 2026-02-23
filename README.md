# Dash Server
https://dashblocks-server.vercel.app

## Available methods:
- `/session` - session with user info
- `/auth/login` - login via user ID and password
- `/auth/logout` - logout (clear session)
- `/get-project/:id` - get project ZIP by project ID
- `/save-project` - save binary data of project to server as ZIP (must have an active session)

## User Interface:
- `/login` - login
- `/upload-project` - upload project (.dbp format only)

## Learn more:

### Every request:
Server will return `ok` boolean key, this key reports whether your request was completed successfully or not

---

### `/session`
Session of current user
#### Request requirement:
- Must have an active session, if not, `401` error code will be returned
#### Response object keys:
- `userId` - ID of logged in user
- `username` - username of logged in user

---

### `/auth/login`
Log in into user's session
#### Request requirement:
- User ID and password are must be correct, if not, `401` error code will be returned
#### Request body parameters:
- `userId` - ID of target user
- `password` - password of target user
#### Response object keys:
- `userId` - ID of logged in user
- `username` - username of logged in user

---

### `/auth/logout`
Log out from user's session
#### Request requirement:
- Must have an active session, if not, `401` error code will be returned

---

### `/get-project/:id`
Get saved ZIP-archive of project from the server by ID
#### Request requirements:
- `:id` - in call should be replaced with the real ID
- Project must exist, if not, `404` error code will be returned

---

### `/save-project`
Save binary data of project to the server as ZIP
#### Request requirements:
- Must have an active session, if not, `401` error code will be returned
- File must be binary
#### Request body parameters:
- `file` - binary data of project
- `name` - name of project
#### Response object key:
- `projectId` - ID of project (can be fetched by `/get-project/:id`)