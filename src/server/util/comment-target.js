const byId = (index, id) => Object.values(index.users).find(user => String(user.id) === String(id));

export const isCommentMessage = message => ["project-commented", "profile-commented", "studio-commented", "comment-replied"].includes(message.type);

export const commentTarget = (index, scope, id) => {
	if (scope === "projects") {
		for (const owner of Object.values(index.users)) {
			const item = (owner.projects || []).find(project => String(project.id) === String(id));
			if (item) return { item, owner };
		}
	} else if (scope === "users") {
		const item = byId(index, id);
		if (item && Object.hasOwn(item, "id")) return { item, owner: item };
	} else if (scope === "studios") {
		const item = index.studios?.[id];
		if (item && Object.hasOwn(item, "id")) return { item, owner: byId(index, item.ownerId) };
	}
	return null;
};
