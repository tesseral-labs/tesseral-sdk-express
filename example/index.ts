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
    publishableKey: "publishable_key_d5s89fdxpxrsbwgi1e6pf5qmz",
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
