import sharp from "sharp";

const AVATAR_SIZE = 64;
const THUMBNAIL_WIDTH = 480;
const THUMBNAIL_HEIGHT = 360;
const ALLOWED_IMAGE_FORMATS = new Set(["jpeg", "png", "webp", "gif", "svg", "avif", "heif"]);

const validateImageBuffer = async (buffer) => {
	try {
		const metadata = await sharp(buffer).metadata();
		return ALLOWED_IMAGE_FORMATS.has(metadata.format);
	} catch (_) {
		return false;
	}
};

const formatAvatarImage = async (buffer) => {
	if (!(await validateImageBuffer(buffer))) {
		throw new Error("Invalid image file");
	}

	return sharp(buffer)
		.rotate()
		.resize(AVATAR_SIZE, AVATAR_SIZE, {
			fit: "cover",
			position: "centre"
		})
		.png({
			compressionLevel: 9,
			adaptiveFiltering: true,
			quality: 80
		})
		.toBuffer();
};

const formatThumbnailImage = async (buffer) => {
	if (!(await validateImageBuffer(buffer))) {
		throw new Error("Invalid image file");
	}

	return sharp(buffer)
		.rotate()
		.resize(THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT, {
			fit: "cover",
			position: "centre"
		})
		.png({
			compressionLevel: 9,
			adaptiveFiltering: true,
			quality: 80
		})
		.toBuffer();
};

export { formatAvatarImage, formatThumbnailImage };
