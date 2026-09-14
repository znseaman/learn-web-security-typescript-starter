import type { RequestHandler } from "express";
import { sendErrorPage } from "./errors.ts";
import { timingSafeEqual } from "node:crypto";

export function validateRequestOrigin(appOrigin: string): RequestHandler {
  return (req, res, next) => {
    if (req.method !== "POST") return next();

    const presentedOrigin = req.header("Origin");
    if (presentedOrigin && presentedOrigin === appOrigin) return next();

    if (presentedOrigin && presentedOrigin !== appOrigin) {
      return sendErrorPage(
        res,
        403,
        "Forbidden",
        "This request did not come from Barely Secure.",
      );
    }

    const presentedReferer = req.header("Referer");
    try {
      if (presentedReferer && new URL(presentedReferer).origin === appOrigin) {
        return next();
      }
    } catch {
      return sendErrorPage(
        res,
        403,
        "Forbidden",
        "This request did not come from Barely Secure.",
      );
    }

    return sendErrorPage(
      res,
      403,
      "Forbidden",
      "This request did not come from Barely Secure.",
    );
  };
}

export function csrfTokensMatch(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") return false;

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);

  if (expectedBuffer.length !== actualBuffer.length) return false;

  return timingSafeEqual(expectedBuffer, actualBuffer);
}
