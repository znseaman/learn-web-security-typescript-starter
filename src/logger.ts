import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

type LogFields = Record<string, unknown>;

const logPath = join(process.cwd(), "data", "bearly-secure.log");

const REDACTED_KEYS = new Set([
  "email",
  "shippingName",
  "shippingAddress",
  "shippingCity",
  "shippingRegion",
  "shippingPostalCode",
  "originalName",
  "sessionId",
  "resetToken",
  "resetLink",
  "secret",
  "adminNotes",
  "storagePath",
]);

function redact(fields: LogFields): LogFields {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => [
      key,
      REDACTED_KEYS.has(key) ? "[REDACTED]" : value,
    ]),
  );
}

export function logEvent(eventName: string, fields: LogFields = {}): void {
  mkdirSync(dirname(logPath), { recursive: true });

  appendFileSync(
    logPath,
    `${JSON.stringify({
      timestamp: new Date().toISOString(),
      event: eventName,
      ...redact(fields),
    })}\n`,
  );
}
