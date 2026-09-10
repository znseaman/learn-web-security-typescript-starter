import { Router } from "express";
import type { Dependencies } from "../dependencies.ts";
import { getCurrentSession } from "../auth/sessions.ts";
import {
  findOrderById,
  listAllOrders,
  listOrderItems,
  listOrdersForUser,
} from "../orders/index.ts";
import { listAllProducts } from "../products.ts";
import { findApiKey } from "../auth/apiKeys.ts";

export function createApiRouter(deps: Dependencies): Router {
  const { db } = deps;
  const router = Router();

  router.get("/api/account/orders", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    res.json({ orders: listOrdersForUser(db, current.user.id) });
  });

  router.get("/api/orders/:id", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const orderId = Number(req.params.id);
    if (!Number.isSafeInteger(orderId)) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    const order = findOrderById(db, orderId);
    if (!order) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    if (order.user_id !== current.user.id) {
      res.status(404).json({ error: "Order not found" });
      return;
    }

    res.json({ order, items: listOrderItems(db, order.id) });
  });

  router.get("/api/products", (_req, res) => {
    res.json({ products: listAllProducts(db) });
  });

  router.get("/api/integrations/warehouse/orders", (req, res) => {
    const apiKey = findApiKey(db, req.header("x-api-key") ?? "");
    if (!apiKey) {
      res.status(401).json({ error: "Invalid API key" });
      return;
    }

    if (apiKey.scope !== "orders:read") {
      res.status(403).json({ error: "API key scope is not allowed" });
      return;
    }

    const orders = listAllOrders(db).map((order) => ({
      id: order.id,
      status: order.status,
      total_cents: order.total_cents,
      created_at: order.created_at,
    }));

    res.json({
      integration: "Warehouse Fulfillment Integration",
      orders,
    });
  });

  return router;
}
