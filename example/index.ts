import express from "express";
import {
  accessTokenClaims,
  credentials,
  organizationId,
  requireAuth,
} from "../src";

const app = express();
app.use(
  requireAuth({
    publishableKey: "publishable_key_7xykm6byxrltz8hk3gvpjbsv0",
    configApiHostname: "config.tesseral.example.com",
  }),
);

app.get("/", (req, res) => {
  res.json({
    organizationId: organizationId(req),
    accessTokenClaims: accessTokenClaims(req),
    credentials: credentials(req),
  });
});

app.listen(8080, "localhost", () => {
  console.log("Listening on http://localhost:8080");
});
