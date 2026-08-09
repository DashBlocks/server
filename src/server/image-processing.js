import sharp from "sharp";

const AVATAR_SIZE = 64;
const THUMBNAIL_WIDTH = 480;
const THUMBNAIL_HEIGHT = 360;
const MAX_INPUT_PIXELS = 50_000_000;
const MAX_DIMENSION = 10000;
const ALLOWED_IMAGE_FORMATS = new Set(["jpeg", "png", "webp", "gif", "svg", "avif", "heif"]);

const validateImageMetadata = async (buffer) => {
	const image = sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS });
	const metadata = await image.metadata();

	if (!ALLOWED_IMAGE_FORMATS.has(metadata.format)) {
		throw new Error("Unsupported image format");
	}

	if (!metadata.width || !metadata.height) {
		throw new Error("Invalid image file");
	}

	if (metadata.width > MAX_DIMENSION || metadata.height > MAX_DIMENSION) {
		throw new Error("Image dimensions too large");
	}

	if (metadata.width * metadata.height > MAX_INPUT_PIXELS) {
		throw new Error("Image dimensions too large");
	}

	return image;
};

const createProcessedBuffer = async (buffer, width, height) => {
	const image = await validateImageMetadata(buffer);
	return image
		.rotate()
		.resize(width, height, {
			fit: "cover",
			position: "centre",
			fastShrinkOnLoad: true
		})
		.png({
			compressionLevel: 9,
			adaptiveFiltering: true
		})
		.toBuffer();
};

const formatAvatarImage = async (buffer) => createProcessedBuffer(buffer, AVATAR_SIZE, AVATAR_SIZE);
const formatThumbnailImage = async (buffer) => createProcessedBuffer(buffer, THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT);

export { formatAvatarImage, formatThumbnailImage };
