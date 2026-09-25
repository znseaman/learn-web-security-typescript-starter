import type { RequestHandler, Response } from "express";

export type LoadSheddingOptions = {
  maxConcurrent: number;
  retryAfterSeconds: number;
};

export function validateLoadSheddingOptions(
  options: LoadSheddingOptions,
): void {
  if (
    !Number.isSafeInteger(options.maxConcurrent) ||
    options.maxConcurrent <= 0
  ) {
    throw new Error("In-flight limit must be a positive integer");
  }
  if (
    !Number.isSafeInteger(options.retryAfterSeconds) ||
    options.retryAfterSeconds <= 0
  ) {
    throw new Error("Retry delay must be a positive integer");
  }
}

export function rejectLoadShedding(
  response: Response,
  options: LoadSheddingOptions,
): void {
  response.setHeader("X-In-Flight-Limit", String(options.maxConcurrent));
  response.setHeader("Retry-After", String(options.retryAfterSeconds));
  response.status(503).json({ error: "Service is at capacity" });
}

function createInFlightRequestCounter() {
  let inFlightRequestCount = 0;

  return {
    startRequest: () => {
      inFlightRequestCount++;
      return inFlightRequestCount;
    },
    endRequest: () => {
      if (inFlightRequestCount > 0) {
        inFlightRequestCount--;
      }
      return inFlightRequestCount;
    },
    getCount: () => inFlightRequestCount,
  };
}

export function createLoadShedder(
  options: LoadSheddingOptions,
): RequestHandler {
  validateLoadSheddingOptions(options);

  let inFlightCounter = createInFlightRequestCounter();

  return (req, res, next) => {
    res.setHeader("X-In-Flight-Limit", String(options.maxConcurrent));

    if (inFlightCounter.getCount() >= options.maxConcurrent) {
      rejectLoadShedding(res, options);
      return;
    }

    let currentInFlightCount = inFlightCounter.startRequest();
    req.once("finish", () => {
      if (currentInFlightCount === inFlightCounter.getCount()) {
        currentInFlightCount = inFlightCounter.endRequest();
      }
    });
    req.once("close", () => {
      if (currentInFlightCount === inFlightCounter.getCount()) {
        currentInFlightCount = inFlightCounter.endRequest();
      }
    });

    next();
  };
}
