import {
  decryptWithKeyring,
  deserializeEncryptedPayload,
  encryptWithKeyring,
  serializeEncryptedPayload,
  type Keyring,
} from "../storage/keyring.ts";

export type ShippingDetails = {
  name: string;
  address: string;
  city: string;
  region: string;
  postalCode: string;
};

export function encryptShippingDetails(
  details: ShippingDetails,
  keyring: Keyring | undefined,
): string {
  const stringifiedDetails = JSON.stringify(details);
  const encrypted = encryptWithKeyring(
    Buffer.from(stringifiedDetails, "utf-8"),
    keyring,
  );
  return serializeEncryptedPayload(encrypted).toString("utf-8");
}

export function decryptShippingDetails(
  serialized: string,
  keyring: Keyring | undefined,
): ShippingDetails {
  let details: unknown;
  try {
    const deserialized = deserializeEncryptedPayload(
      Buffer.from(serialized, "utf-8"),
    );
    const decryptedPayload = decryptWithKeyring(deserialized, keyring);
    details = JSON.parse(decryptedPayload.toString("utf-8"));
  } catch {
    throw new Error("Invalid shipping details");
  }

  if (!isShippingDetails(details)) {
    throw new Error("Invalid shipping details");
  }

  return details;
}

function isShippingDetails(details: unknown): details is ShippingDetails {
  if (!details || typeof details !== "object") {
    return false;
  }

  const candidate = details as Record<string, unknown>;
  return (
    typeof candidate.name === "string" &&
    typeof candidate.address === "string" &&
    typeof candidate.city === "string" &&
    typeof candidate.region === "string" &&
    typeof candidate.postalCode === "string"
  );
}
