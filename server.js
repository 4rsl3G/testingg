const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const {
  ensureState,
  loginEmail,
  requestOTP,
  verifyOTP,
  getMerchantId,
  searchJournals,
} = require("./gobizStateless");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const COOKIE_NAME = process.env.COOKIE_NAME || "gobiz_auth";
const COOKIE_KEY = Buffer.from(process.env.COOKIE_KEY_BASE64, "base64");

if (COOKIE_KEY.length !== 32) {
  throw new Error("COOKIE_KEY_BASE64 harus 32 bytes base64 (AES-256-GCM).");
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({
  contentSecurityPolicy: false, // supaya gampang (kalau mau ketat bisa kita rapihin)
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

// basic rate limit
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
}));

function seal(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", COOKIE_KEY, iv);
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(json), cipher.final()]);
  const tag = cipher.getAuthTag();
  // iv|tag|ciphertext => base64
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function unseal(b64) {
  const raw = Buffer.from(b64, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", COOKIE_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString("utf8"));
}

function getStateFromCookie(req) {
  try {
    const v = req.cookies[COOKIE_NAME];
    if (!v) return ensureState(null);
    return ensureState(unseal(v));
  } catch {
    return ensureState(null);
  }
}

function setStateCookie(res, state) {
  const payload = {
    accessToken: state.accessToken,
    refreshToken: state.refreshToken,
    tokenExpiry: state.tokenExpiry,
    uniqueId: state.uniqueId,
    ua: state.ua,
    lastRequest: state.lastRequest,
  };

  res.cookie(COOKIE_NAME, seal(payload), {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // kalau sudah https: true
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

function clearStateCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function requireAuth(req, res, next) {
  const state = getStateFromCookie(req);
  if (!state.accessToken) return res.redirect("/login");
  req.gobizState = state;
  next();
}

function jakartaISODate() {
  const d = new Date();
  const utc = d.getTime() + d.getTimezoneOffset() * 60_000;
  const jkt = new Date(utc + 7 * 60 * 60_000);
  return jkt.toISOString().slice(0, 10);
}

// ===== Pages =====

app.get("/", (req, res) => {
  const state = getStateFromCookie(req);
  if (state.accessToken) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login/email", async (req, res) => {
  try {
    const { email, password } = req.body;
    let state = getStateFromCookie(req);

    state = await loginEmail(state, email, password);
    setStateCookie(res, state);
    return res.redirect("/dashboard");
  } catch (e) {
    return res.status(400).render("login", { error: "Login gagal. Coba lagi." });
  }
});

app.get("/otp", (req, res) => {
  res.render("otp", { step: "request", error: null, otpToken: null, otpLength: 6 });
});

app.post("/otp/request", async (req, res) => {
  try {
    const { phone, countryCode } = req.body;
    let state = getStateFromCookie(req);

    const r = await requestOTP(state, phone, countryCode || "62");
    // simpan state (uniqueId/ua) di cookie juga
    setStateCookie(res, r.state);

    // otpToken jangan masuk cookie (lebih aman), cukup hidden field di form
    return res.render("otp", {
      step: "verify",
      error: null,
      otpToken: r.otpToken,
      otpLength: r.otpLength || 6,
    });
  } catch {
    return res.status(400).render("otp", { step: "request", error: "Gagal request OTP.", otpToken: null, otpLength: 6 });
  }
});

app.post("/otp/verify", async (req, res) => {
  try {
    const { otp, otpToken } = req.body;
    let state = getStateFromCookie(req);

    state = await verifyOTP(state, otp, otpToken);
    setStateCookie(res, state);
    return res.redirect("/dashboard");
  } catch {
    return res.status(400).render("otp", { step: "request", error: "OTP salah / expired.", otpToken: null, otpLength: 6 });
  }
});

app.post("/logout", (req, res) => {
  clearStateCookie(res);
  return res.redirect("/login");
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    let state = req.gobizState;

    const r = await getMerchantId(state);
    state = r.state;
    setStateCookie(res, state);

    res.render("dashboard", {
      merchantId: r.merchantId || null,
      today: jakartaISODate(),
      error: null,
    });
  } catch (e) {
    clearStateCookie(res);
    return res.redirect("/login");
  }
});

// ===== API for polling (frontend setInterval fetch) =====

app.get("/api/mutasi", requireAuth, async (req, res) => {
  try {
    let state = req.gobizState;

    const merchantId = String(req.query.merchantId || "");
    if (!merchantId) return res.status(400).json({ ok: false, message: "merchantId required" });

    const d = String(req.query.date || jakartaISODate());
    const fromISO = `${d}T00:00:00+07:00`;
    const toISO = `${d}T23:59:59+07:00`;

    const r = await searchJournals(state, merchantId, fromISO, toISO);
    state = r.state;
    setStateCookie(res, state);

    return res.json({ ok: true, hits: r.data.hits || [] });
  } catch (e) {
    if (e.message === "SESSION_EXPIRED" || e.message === "NOT_LOGGED_IN") {
      clearStateCookie(res);
      return res.status(401).json({ ok: false, message: "SESSION_EXPIRED" });
    }
    return res.status(500).json({ ok: false, message: "FAILED", detail: e.payload || null });
  }
});

app.listen(PORT, () => {
  console.log(`Running on http://localhost:${PORT}`);
});
