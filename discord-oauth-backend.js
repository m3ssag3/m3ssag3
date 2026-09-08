// discord-oauth-backend.js
// Энэ кодыг таны bot аль хэдийн ажиллуулж байгаа Express серверт (status endpoint
// хариулж байгаа хэсэгт) нэмнэ. Хэрэв танайд аль хэдийн SQLite db instance байгаа бол
// доорх "const db = ..." мөрийг тэрийгээ дуудаж байгаагаар солино — шинэ файл үүсгэх
// албагүй, зөвхөн `reviews` table-ыг л нэмнэ.
//
// npm install express cors jsonwebtoken better-sqlite3
//
// Environment variables (bot host-ынхоо "Environment" / "Secrets" хэсэгт нэмнэ):
//   DISCORD_CLIENT_ID     = 1541874591243444356
//   DISCORD_CLIENT_SECRET = <Developer Portal → OAuth2 → Client Secret>
//   SESSION_SECRET        = <random 32+ тэмдэгттэй string, өөрөө үүсгэ>
//   FRONTEND_ORIGIN        = https://m3ssag3.github.io

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express(); // хэрэв өөр app байгаа бол шинээр үүсгэлгүй тэрийг нь ашигла
app.use(express.json());

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  SESSION_SECRET,
  FRONTEND_ORIGIN,
} = process.env;

const REDIRECT_URI = "https://o3nua77ki9.apps.bot-hosting.cloud/auth/discord/callback";

app.use(cors({ origin: FRONTEND_ORIGIN }));

// --- Database ---
const db = new Database("messAge.db"); // байгаа bot db файлаа заавал энд заа
db.exec(`
  CREATE TABLE IF NOT EXISTS reviews (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    avatar_url TEXT,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

// --- Auth helpers ---
function verifySession(token) {
  try { return jwt.verify(token, SESSION_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const user = verifySession(token);
  if (!user) return res.status(401).json({ error: "invalid session" });
  req.user = user;
  next();
}

// Алхам 2: Discord code-той redirect ирнэ → token-той сольж, JWT үүсгэж, GitHub Pages рүү буцаана
app.get("/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send("Missing code");

  try {
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });
    if (!tokenRes.ok) throw new Error("token exchange failed: " + (await tokenRes.text()));
    const tokenData = await tokenRes.json();

    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userRes.ok) throw new Error("failed to fetch user");
    const discordUser = await userRes.json();

    // Энд өөрийн database дээр account үүсгэх/шинэчлэх логикоо нэм (state === 'signup' | 'login')

    const avatarUrl = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : null;

    const sessionToken = jwt.sign(
      { id: discordUser.id, username: discordUser.username, avatarUrl },
      SESSION_SECRET,
      { expiresIn: "7d" }
    );

    res.redirect(`${FRONTEND_ORIGIN}/#session=${sessionToken}&mode=${state || "login"}`);
  } catch (err) {
    console.error(err);
    res.redirect(`${FRONTEND_ORIGIN}/#auth_error=1`);
  }
});

// Алхам 3: Frontend энэ endpoint-оор session token-оо баталгаажуулж, profile-оо авна
app.get("/api/me", requireAuth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, avatarUrl: req.user.avatarUrl });
});

// --- Reviews ---

// Нийтэд харагдах review жагсаалт. Хэрэв caller нэвтэрсэн бол өөрийн review-г isMine:true
// гэж тэмдэглэнэ (frontend түүгээрээ form-оо pre-fill хийнэ).
app.get("/api/reviews", (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const me = token ? verifySession(token) : null;

  const rows = db.prepare("SELECT * FROM reviews ORDER BY created_at DESC").all();
  const reviews = rows.map(r => ({
    username: r.username,
    avatarUrl: r.avatar_url,
    rating: r.rating,
    body: r.body,
    createdAt: r.created_at,
    isMine: me ? me.id === r.user_id : false,
  }));
  const average = reviews.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
  res.json({ reviews, average });
});

// Нэвтэрсэн хэрэглэгч review үлдээх/шинэчлэх — нэг user_id-д зөвхөн нэг мөр (upsert).
app.post("/api/reviews", requireAuth, (req, res) => {
  const { rating, body } = req.body || {};
  const r = Number(rating);
  const text = String(body || "").trim().slice(0, 500);
  if (!Number.isInteger(r) || r < 1 || r > 5) return res.status(400).json({ error: "rating must be 1-5" });
  if (!text) return res.status(400).json({ error: "body required" });

  db.prepare(`
    INSERT INTO reviews (user_id, username, avatar_url, rating, body, created_at)
    VALUES (@id, @username, @avatarUrl, @rating, @body, @createdAt)
    ON CONFLICT(user_id) DO UPDATE SET
      username = excluded.username,
      avatar_url = excluded.avatar_url,
      rating = excluded.rating,
      body = excluded.body,
      created_at = excluded.created_at
  `).run({
    id: req.user.id,
    username: req.user.username,
    avatarUrl: req.user.avatarUrl,
    rating: r,
    body: text,
    createdAt: new Date().toISOString(),
  });

  res.json({ ok: true });
});

// Хэрэглэгч өөрийн review-гээ устгах
app.delete("/api/reviews/me", requireAuth, (req, res) => {
  db.prepare("DELETE FROM reviews WHERE user_id = ?").run(req.user.id);
  res.json({ ok: true });
});

module.exports = app; // эсвэл app.listen(...) — таны одоо байгаа сервертэй хэрхэн нийлүүлж буйгаас хамаарна
