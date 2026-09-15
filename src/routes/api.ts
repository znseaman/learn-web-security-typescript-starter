import { Router } from "express";
import type { Dependencies } from "../dependencies.ts";
import { getCurrentSession } from "../auth/sessions.ts";
import {
  findOrderById,
  listAllOrders,
  listOrderItems,
  listOrdersForUser,
  type Order,
  type OrderItem,
} from "../orders/index.ts";
import { listProducts, type Product } from "../products.ts";
import { findApiKey } from "../auth/apiKeys.ts";

type ProductResponse = {
  id: number;
  name: string;
  description: string;
  image_path: string;
  price_cents: number;
};

type OrderResponse = {
  id: number;
  status: Order["status"];
  total_cents: number;
  created_at: string;
};

type OrderItemResponse = {
  product_id: number;
  product_name: string;
  quantity: number;
  price_cents: number;
};

function toProductResponse(product: Product): ProductResponse {
  return {
    id: product.id,
    name: product.name,
    description: product.description,
    image_path: product.image_path,
    price_cents: product.price_cents,
  };
}

function toOrderResponse(order: Order): OrderResponse {
  return {
    id: order.id,
    status: order.status,
    total_cents: order.total_cents,
    created_at: order.created_at,
  };
}

function toOrderItemResponse(orderItem: OrderItem): OrderItemResponse {
  return {
    product_id: orderItem.product_id,
    product_name: orderItem.product_name,
    quantity: orderItem.quantity,
    price_cents: orderItem.price_cents,
  };
}

export function createApiRouter(deps: Dependencies): Router {
  const { db } = deps;
  const router = Router();

  router.get("/api/account/orders", (req, res) => {
    const current = getCurrentSession(db, req.header("cookie"));
    if (!current) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const orders = listOrdersForUser(db, current.user.id);
    res.json({ orders: orders.map(toOrderResponse) });
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

    const items = listOrderItems(db, order.id);
    res.json({
      order: toOrderResponse(order),
      items: items.map(toOrderItemResponse),
    });
  });

  router.get("/api/products", (_req, res) => {
    const products = listProducts(db);
    res.json({ products: products.map(toProductResponse) });
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
