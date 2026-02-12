const axios = require("axios");
const crypto = require("crypto");
const UserAgents = require("user-agents");

const BASE_URL = "https://api.gobiz.co.id";

const http = axios.create({
  timeout: 30000,
  validateStatus: () => true,
});

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function rateLimit(state) {
  const minInterval = 2000;
  const diff = Date.now() - (state.lastRequest || 0);
  if (diff < minInterval) await sleep(minInterval - diff);
  state.lastRequest = Date.now();
}

function ensureState(state) {
  const s = state && typeof state === "object" ? state : {};
  return {
    accessToken: s.accessToken || null,
    refreshToken: s.refreshToken || null,
    tokenExpiry: s.tokenExpiry || null,
    uniqueId: s.uniqueId || crypto.randomUUID(),
    ua: s.ua || new UserAgents({ deviceCategory: "desktop" }).toString(),
    lastRequest: s.lastRequest || 0,
  };
}

function headers(state, auth = false) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json, text/plain, */*",
    "Accept-Language": "id",
    Origin: "https://portal.gofoodmerchant.co.id",
    Referer: "https://portal.gofoodmerchant.co.id/",
    "Authentication-Type": "go-id",
    "Gojek-Country-Code": "ID",
    "Gojek-Timezone": "Asia/Jakarta",
    "X-Appid": "go-biz-web-dashboard",
    "X-Appversion": "platform-v3.97.0-b986b897",
    "X-Deviceos": "Web",
    "X-Phonemake": "Windows 10 64-bit",
    "X-Phonemodel": "Chrome 143.0.0.0 on Windows 10 64-bit",
    "X-Platform": "Web",
    "X-Uniqueid": state.uniqueId,
    "X-User-Type": "merchant",
    "User-Agent": state.ua,
    ...(auth ? { Authorization: `Bearer ${state.accessToken}` } : {}),
  };
}

function setTokens(state, tokenRes) {
  state.accessToken = tokenRes.access_token;
  state.refreshToken = tokenRes.refresh_token || state.refreshToken;
  state.tokenExpiry = Date.now() + (tokenRes.expires_in * 1000);
}

async function loginEmail(state, email, password) {
  state = ensureState(state);

  await rateLimit(state);
  await http.post(
    `${BASE_URL}/goid/login/request`,
    { email, login_type: "password", client_id: "go-biz-web-new" },
    { headers: headers(state, false) }
  );

  await sleep(2500);

  await rateLimit(state);
  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "password",
      data: { email, password, user_type: "merchant" },
    },
    { headers: headers(state, false) }
  );

  if (res.status !== 200) throw new Error("LOGIN_FAILED");
  setTokens(state, res.data);
  return state;
}

async function requestOTP(state, phone, countryCode = "62") {
  state = ensureState(state);

  await rateLimit(state);
  const res = await http.post(
    `${BASE_URL}/goid/login/request`,
    { client_id: "go-biz-web-new", phone_number: phone, country_code: countryCode },
    { headers: { ...headers(state, false), Authorization: "Bearer" } }
  );

  if (res.status !== 200) throw new Error("OTP_REQUEST_FAILED");
  return {
    state,
    otpToken: res.data.data.otp_token,
    expiresIn: res.data.data.otp_expires_in,
    otpLength: res.data.data.otp_length,
  };
}

async function verifyOTP(state, otp, otpToken) {
  state = ensureState(state);

  await rateLimit(state);
  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "otp",
      data: { otp, otp_token: otpToken },
    },
    { headers: { ...headers(state, false), Authorization: "Bearer" } }
  );

  if (res.status !== 200) throw new Error("OTP_VERIFY_FAILED");
  setTokens(state, res.data);
  return state;
}

async function refreshToken(state) {
  state = ensureState(state);
  if (!state.refreshToken) return { state, ok: false };

  await rateLimit(state);
  const res = await http.post(
    `${BASE_URL}/goid/token`,
    {
      client_id: "go-biz-web-new",
      grant_type: "refresh_token",
      data: { refresh_token: state.refreshToken, user_type: "merchant" },
    },
    { headers: headers(state, false) }
  );

  if (res.status !== 200) {
    state.accessToken = null;
    state.refreshToken = null;
    state.tokenExpiry = null;
    return { state, ok: false };
  }

  setTokens(state, res.data);
  return { state, ok: true };
}

async function authRequest(state, method, url, data) {
  state = ensureState(state);
  if (!state.accessToken) throw new Error("NOT_LOGGED_IN");

  await rateLimit(state);
  let res = await http.request({ method, url, data, headers: headers(state, true) });

  if (res.status === 401) {
    const r = await refreshToken(state);
    state = r.state;
    if (!r.ok) throw new Error("SESSION_EXPIRED");

    await rateLimit(state);
    res = await http.request({ method, url, data, headers: headers(state, true) });
  }

  if (res.status < 200 || res.status >= 300) {
    const err = new Error("REQUEST_FAILED");
    err.payload = res.data;
    err.status = res.status;
    throw err;
  }

  return { state, data: res.data };
}

async function getMerchantId(state) {
  const r = await authRequest(
    state,
    "POST",
    `${BASE_URL}/v1/merchants/search`,
    { from: 0, to: 1, _source: ["id"] }
  );
  return { state: r.state, merchantId: r.data.hits?.[0]?.id };
}

async function searchJournals(state, merchantId, fromISO, toISO) {
  return authRequest(
    state,
    "POST",
    `${BASE_URL}/journals/search`,
    {
      from: 0,
      size: 50,
      sort: { time: { order: "desc" } },
      included_categories: { incoming: ["transaction_share", "action"] },
      query: [{
        op: "and",
        clauses: [
          { field: "metadata.transaction.merchant_id", op: "equal", value: merchantId },
          { field: "metadata.transaction.transaction_time", op: "gte", value: fromISO },
          { field: "metadata.transaction.transaction_time", op: "lte", value: toISO }
        ],
      }],
    }
  );
}

module.exports = {
  ensureState,
  loginEmail,
  requestOTP,
  verifyOTP,
  refreshToken,
  authRequest,
  getMerchantId,
  searchJournals
};
