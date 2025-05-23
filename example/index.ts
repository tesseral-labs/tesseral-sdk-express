import express from "express";
import {
  accessTokenClaims,
  credentials,
  organizationId,
  requireAuth,
} from "../src";
import dotenv from "dotenv";
import path from "path";

dotenv.config({
  path: path.resolve(__dirname + "/.env"),
});

const app = express();
app.use(
  requireAuth({
    apiKeysEnabled: true,
    publishableKey: process.env.TESSERAL_PUBLISHABLE_KEY || "",
    configApiHostname: "config.tesseral.com",
  })
);

app.get("/", (req, res) => {
  res.json({
    organizationId: organizationId(req),
    accessTokenClaims: accessTokenClaims(req),
    credentials: credentials(req),
  });
});

app.post("/", (req, res) => {
  res.json({
    organizationId: organizationId(req),
    credentials: credentials(req),
  });
});

app.listen(8080, "localhost", () => {
  console.log("Listening on http://localhost:8080");
});
