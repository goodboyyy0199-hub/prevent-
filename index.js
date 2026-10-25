/**
 * Discord Security Bot: Anti-Link / Anti-Spam / Anti-Nuke / Security Log
 * Node.js 18+ | discord.js v14
 */
require('dotenv').config();
const {
  Client,
  GatewayIntentBits,
  Partials,
  EmbedBuilder,
  AuditLogEvent,
  PermissionFlagsBits,
  Events,
} = require('discord.js');

/* ============================================================
 *  ส่วนตั้งค่า (CONFIG)
 * ============================================================ */

// ---- ค่าจากไฟล์ .env ----
const TOKEN = process.env.DISCORD_TOKEN;

// [LOG CHANNEL ID] ห้องที่บอทจะส่ง Embed Log ไป
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;

// [ALLOWED ROLES] ยศที่ "ได้รับอนุญาตให้ส่งลิงก์" (ใส่ใน .env คั่นด้วย ,)
const ALLOWED_ROLE_IDS = (process.env.ALLOWED_ROLE_IDS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

// ผู้ใช้ที่ไว้ใจเต็มที่ (ข้าม Anti-Nuke)
const TRUSTED_USER_IDS = (process.env.TRUSTED_USER_IDS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

// ---- Anti-Link ----
const LINK_WARNING_TEXT = 'ไม่อนุญาตให้ส่งลิงก์ หากต้องการส่งต้องได้รับอนุญาตก่อน';
// true = คนที่มีสิทธิ์ Administrator ส่งลิงก์ได้โดยไม่ต้องมียศใน ALLOWED_ROLE_IDS
const ADMINISTRATORS_BYPASS = true;

// ---- Anti-Spam ----
const SPAM = {
  WINDOW_MS: 3000,        // ช่วงเวลาตรวจจับ (3 วินาที)
  MAX_MESSAGES: 4,        // ส่งเกิน 4 ข้อความในช่วงเวลา = สแปม
  MAX_DUPLICATES: 3,      // ข้อความเดิมซ้ำครบ 3 ครั้งในช่วงเวลา = สแปม
  MAX_MENTIONS: 4,        // แท็กเกิน 4 คนในข้อความเดียว = Mass Mention
  TIMEOUT_MS: 5 * 60 * 1000, // Timeout 5 นาที
};

// ---- Anti-Nuke ----
const NUKE = {
  // [THRESHOLD] ลบเกิน 2 ครั้ง ภายใน 5000ms = ถือว่า Nuke
  // (ลบครั้งที่ 3 ในช่วง 5 วินาทีจะโดนทันที)
  LIMIT: 2,
  WINDOW_MS: 5000,
};

/* ============================================================
 *  สร้าง Client + Intents
 * ============================================================ */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,      // [Privileged] Server Members Intent
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,    // [Privileged] Message Content Intent
    GatewayIntentBits.GuildModeration,   // จำเป็นสำหรับ guildAuditLogEntryCreate (Audit Log)
  ],
  partials: [Partials.Message, Partials.Channel],
});

/* ============================================================
 *  Helper: Security Log
 * ============================================================ */
let logChannelCache = null;

async function sendLog({ title, color, userId, reason, fields = [] }) {
  try {
    if (!logChannelCache) {
      logChannelCache = await client.channels.fetch(LOG_CHANNEL_ID).catch(() => null);
    }
    if (!logChannelCache) return console.warn('[LOG] ไม่พบห้อง Security Log ตรวจสอบ LOG_CHANNEL_ID');

    const embed = new EmbedBuilder()
      .setTitle(title)
      .setColor(color)
      .addFields(
        { name: 'ผู้กระทำ', value: `<@${userId}>\nID: \`${userId}\``, inline: true },
        { name: 'สาเหตุ', value: reason, inline: true },
        ...fields,
      )
      .setTimestamp();

    await logChannelCache.send({ embeds: [embed] });
  } catch (err) {
    console.error('[LOG] ส่ง log ไม่สำเร็จ:', err.message);
  }
}

// ส่งข้อความเตือนแล้วลบตัวเองหลัง 8 วินาที เพื่อไม่ให้แชทรก
async function warn(channel, content) {
  try {
    const msg = await channel.send({ content, allowedMentions: { parse: ['users'] } });
    setTimeout(() => msg.delete().catch(() => {}), 8000);
  } catch { /* ไม่มีสิทธิ์ส่งข้อความ ข้ามไป */ }
}

const truncate = (s, n = 900) => (s.length > n ? s.slice(0, n) + '…' : s || '(ว่าง)');

/* ============================================================
 *  1) ANTI-LINK
 * ============================================================ */
// ลิงก์ทุกรูปแบบ: http(s)://, www., discord.gg, discord.com/invite และโดเมนเปล่าๆ ที่ลงท้ายด้วย TLD ยอดนิยม
const LINK_REGEX = new RegExp(
  [
    String.raw`https?:\/\/\S+`,
    String.raw`www\.\S+`,
    String.raw`discord(?:app)?\.(?:gg|com\/invite)\/\S+`,
    String.raw`\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|gg|xyz|me|co|info|biz|club|online|site|shop|app|dev|tv|ly|to|cc|ru|cn|th|in\.th|co\.th|link|live|fun|top|icu|ml|tk|ga|cf)\b(?:\/\S*)?`,
  ].join('|'),
  'i',
);

// กันการหลบด้วยตัวอักษรไร้ความกว้าง เช่น dis​cord.gg
function containsLink(text) {
  const cleaned = text.replace(/[\u200B-\u200D\uFEFF\u2060]/g, '');
  return LINK_REGEX.test(cleaned);
}

function hasLinkPermission(member) {
  if (!member) return false;
  if (member.id === member.guild.ownerId) return true;
  if (ADMINISTRATORS_BYPASS && member.permissions.has(PermissionFlagsBits.Administrator)) return true;
  return member.roles.cache.some((r) => ALLOWED_ROLE_IDS.includes(r.id));
}

async function handleAntiLink(message) {
  if (!containsLink(message.content)) return false;
  if (hasLinkPermission(message.member)) return false;

  await message.delete().catch(() => {});
  await warn(message.channel, `${message.author} ${LINK_WARNING_TEXT}`);

  await sendLog({
    title: '🔗 Anti-Link: ลบข้อความที่มีลิงก์',
    color: 0xf1c40f,
    userId: message.author.id,
    reason: 'ส่งลิงก์โดยไม่มียศที่ได้รับอนุญาต',
    fields: [
      { name: 'ห้อง', value: `<#${message.channelId}>`, inline: true },
      { name: 'ข้อความ', value: truncate(message.content) },
    ],
  });
  return true;
}

/* ============================================================
 *  2) ANTI-SPAM
 * ============================================================ */
// เก็บประวัติข้อความล่าสุดของแต่ละคน: key = guildId:userId
const spamHistory = new Map();

async function handleAntiSpam(message) {
  const member = message.member;
  if (!member) return false;
  // ข้ามเจ้าของเซิร์ฟเวอร์ และคนที่มีสิทธิ์ Administrator
  if (member.id === message.guild.ownerId) return false;
  if (member.permissions.has(PermissionFlagsBits.Administrator)) return false;

  const now = Date.now();
  const key = `${message.guildId}:${message.author.id}`;
  const history = (spamHistory.get(key) || []).filter((m) => now - m.ts < SPAM.WINDOW_MS);
  history.push({
    ts: now,
    id: message.id,
    channelId: message.channelId,
    content: message.content.trim().toLowerCase(),
  });
  spamHistory.set(key, history);

  let reason = null;

  // (ก) Mass Mention
  if (message.mentions.users.size > SPAM.MAX_MENTIONS) {
    reason = `Mass Mention (แท็ก ${message.mentions.users.size} คนในข้อความเดียว)`;
  }
  // (ข) ส่งรัวเกินกำหนด
  else if (history.length > SPAM.MAX_MESSAGES) {
    reason = `ส่งข้อความรัว (${history.length} ข้อความใน ${SPAM.WINDOW_MS / 1000} วินาที)`;
  }
  // (ค) ข้อความซ้ำ
  else if (message.content.trim()) {
    const dupes = history.filter((m) => m.content === history[history.length - 1].content).length;
    if (dupes >= SPAM.MAX_DUPLICATES) reason = `ส่งข้อความซ้ำ ${dupes} ครั้งใน ${SPAM.WINDOW_MS / 1000} วินาที`;
  }

  if (!reason) return false;

  spamHistory.delete(key); // ล้างประวัติ กันถูกลงโทษซ้ำ

  // ลบข้อความทั้งหมดในช่วงสแปม
  const idsByChannel = {};
  for (const m of history) (idsByChannel[m.channelId] ||= []).push(m.id);
  for (const [chId, ids] of Object.entries(idsByChannel)) {
    const ch = message.guild.channels.cache.get(chId);
    if (ch) await ch.bulkDelete(ids, true).catch(() => message.delete().catch(() => {}));
  }

  // Timeout 5 นาที
  let punished = false;
  if (member.moderatable) {
    punished = await member.timeout(SPAM.TIMEOUT_MS, `Anti-Spam: ${reason}`).then(() => true).catch(() => false);
  }

  await warn(
    message.channel,
    `${message.author} ตรวจพบการสแปม (${reason}) ${punished ? 'คุณถูก Timeout 5 นาที' : ''}`,
  );

  await sendLog({
    title: '🚫 Anti-Spam: ตรวจพบการสแปม',
    color: 0xe67e22,
    userId: message.author.id,
    reason,
    fields: [
      { name: 'ห้อง', value: `<#${message.channelId}>`, inline: true },
      { name: 'บทลงโทษ', value: punished ? 'ลบข้อความ + Timeout 5 นาที' : 'ลบข้อความ (Timeout ไม่สำเร็จ: ยศบอทต่ำกว่าหรือไม่มีสิทธิ์)', inline: true },
    ],
  });
  return true;
}

/* ============================================================
 *  Message Events
 * ============================================================ */
async function processMessage(message) {
  if (!message.guild || message.author?.bot || message.partial && !message.content) return;
  if (!message.member) message.member = await message.guild.members.fetch(message.author.id).catch(() => null);

  if (await handleAntiLink(message)) return;
  await handleAntiSpam(message);
}

client.on(Events.MessageCreate, (m) => processMessage(m).catch(console.error));

// กันการแก้ไขข้อความใส่ลิงก์ทีหลัง
client.on(Events.MessageUpdate, async (_old, newMsg) => {
  try {
    if (newMsg.partial) newMsg = await newMsg.fetch();
    if (!newMsg.guild || newMsg.author?.bot) return;
    if (!newMsg.member) newMsg.member = await newMsg.guild.members.fetch(newMsg.author.id).catch(() => null);
    await handleAntiLink(newMsg);
  } catch (e) { console.error(e); }
});

/* ============================================================
 *  3) ANTI-NUKE (ใช้ Audit Log แบบ Real-time)
 * ============================================================ */
// เก็บเวลาที่ผู้ใช้แต่ละคนทำแอคชัน: key = action:executorId
const nukeTracker = new Map();
const alreadyPunished = new Set(); // กันแบนซ้ำระหว่างที่กำลังดำเนินการ

const NUKE_ACTIONS = {
  [AuditLogEvent.ChannelDelete]: { name: 'ลบห้อง (Channel Delete)', label: 'ห้อง' },
  [AuditLogEvent.RoleDelete]: { name: 'ลบยศ (Role Delete)', label: 'ยศ' },
};

client.on(Events.GuildAuditLogEntryCreate, async (entry, guild) => {
  try {
    const action = NUKE_ACTIONS[entry.action];
    if (!action) return;

    const executorId = entry.executorId;
    if (!executorId) return;

    // ---- ข้ามคนที่ไว้ใจ: ตัวบอทเอง, เจ้าของเซิร์ฟเวอร์, รายชื่อ TRUSTED_USER_IDS ----
    if (executorId === client.user.id) return;
    if (executorId === guild.ownerId) return;
    if (TRUSTED_USER_IDS.includes(executorId)) return;
    if (alreadyPunished.has(executorId)) return;

    // ---- นับจำนวนครั้งในช่วง WINDOW_MS ----
    const key = `${entry.action}:${executorId}`;
    const now = Date.now();
    const times = (nukeTracker.get(key) || []).filter((t) => now - t < NUKE.WINDOW_MS);
    times.push(now);
    nukeTracker.set(key, times);

    if (times.length <= NUKE.LIMIT) return; // ยังไม่เกิน threshold

    // ===== ตรวจพบ Nuke =====
    alreadyPunished.add(executorId);
    nukeTracker.delete(key);
    setTimeout(() => alreadyPunished.delete(executorId), 30_000);

    const reason = `Anti-Nuke: ${action.name} ${times.length} ${action.label} ภายใน ${NUKE.WINDOW_MS / 1000} วินาที`;
    const member = await guild.members.fetch(executorId).catch(() => null);

    // ขั้นที่ 1: ถอดยศทั้งหมด (Strip Roles) เพื่อยึดสิทธิ์ก่อนทำอย่างอื่น
    let stripped = 'ไม่พบสมาชิกในเซิร์ฟเวอร์';
    if (member) {
      const removable = member.roles.cache.filter((r) => r.id !== guild.id && !r.managed && r.editable);
      stripped = await member.roles.remove(removable, reason)
        .then(() => `ถอด ${removable.size} ยศ`)
        .catch((e) => `ถอดยศไม่สำเร็จ (${e.message})`);
    }

    // ขั้นที่ 2: แบนออกจากเซิร์ฟเวอร์
    const banned = await guild.members.ban(executorId, { reason })
      .then(() => 'แบนสำเร็จ ✅')
      .catch((e) => `แบนไม่สำเร็จ ❌ (${e.message})`);

    await sendLog({
      title: '☢️ Anti-Nuke: ตรวจพบการทำลายเซิร์ฟเวอร์',
      color: 0xe74c3c,
      userId: executorId,
      reason,
      fields: [
        { name: 'ถอดยศ', value: stripped, inline: true },
        { name: 'แบน', value: banned, inline: true },
        { name: 'เป้าหมายล่าสุด', value: `${entry.target?.name ?? entry.targetId ?? 'ไม่ทราบ'}`, inline: false },
      ],
    });
  } catch (err) {
    console.error('[ANTI-NUKE]', err);
  }
});

/* ============================================================
 *  Ready / Cleanup
 * ============================================================ */
client.once(Events.ClientReady, (c) => {
  console.log(`✅ ล็อกอินเป็น ${c.user.tag}`);
  if (!ALLOWED_ROLE_IDS.length) console.warn('⚠️ ยังไม่ได้ตั้ง ALLOWED_ROLE_IDS');
  if (!LOG_CHANNEL_ID) console.warn('⚠️ ยังไม่ได้ตั้ง LOG_CHANNEL_ID');
});

// ล้างข้อมูลเก่าในหน่วยความจำทุก 1 นาที
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of spamHistory) if (!v.some((m) => now - m.ts < SPAM.WINDOW_MS)) spamHistory.delete(k);
  for (const [k, v] of nukeTracker) if (!v.some((t) => now - t < NUKE.WINDOW_MS)) nukeTracker.delete(k);
}, 60_000);

process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));

if (!TOKEN) {
  console.error('❌ ไม่พบ DISCORD_TOKEN ในไฟล์ .env');
  process.exit(1);
}
client.login(TOKEN);
