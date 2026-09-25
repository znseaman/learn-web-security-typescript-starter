import multer from "multer";

export function createUploadMiddleware(fieldName: string, maxBytes: number) {
  return multer({
    limits: {
      fileSize: maxBytes,
      files: 1,
    },
    storage: multer.memoryStorage(),
  }).single(fieldName);
}
