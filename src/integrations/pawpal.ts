import { createHmac, timingSafeEqual } from "node:crypto";

export function createPawPalReference(
  orderId: number,
  totalCents: number,
  apiKey: string,
): string {
  const payload = `${orderId}:${totalCents}`;
  const signature = createHmac("sha256", apiKey)
    .update(payload)
    .digest("hex")
    .slice(0, 16);
  return `pawpal_${orderId}_${signature}`;
}

export function createPawPalCheckoutUrl(orderId: number): string {
  const checkoutUrl = new URL("https://pawpal.example/checkout");
  checkoutUrl.searchParams.set("orderId", String(orderId));
  return checkoutUrl.toString();
}

export type PawPalWebhookVerification =
  | { outcome: "unauthorized" }
  | { outcome: "malformed" }
  | { outcome: "approved"; orderId: number };

export function verifyPawPalWebhook(
  providedKey: string,
  expectedKey: string,
  payload: unknown,
): PawPalWebhookVerification {
  if (
    providedKey.length !== expectedKey.length ||
    !timingSafeEqual(Buffer.from(providedKey), Buffer.from(expectedKey))
  ) {
    return { outcome: "unauthorized" };
  }
  const payloadRecord =
    typeof payload === "object" && payload !== null
      ? (payload as Record<string, unknown>)
      : {};
  const orderId =
    typeof payloadRecord.orderId === "number"
      ? payloadRecord.orderId
      : Number.NaN;

  if (
    !Number.isSafeInteger(orderId) ||
    orderId <= 0 ||
    payloadRecord.status !== "approved"
  ) {
    return { outcome: "malformed" };
  }

  return { outcome: "approved", orderId };
}
