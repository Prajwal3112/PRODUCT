require('dotenv').config();
const axios = require('axios');
const chalk = require('chalk').default; // ✅ Fix here

const GRAYLOG_USER = process.env.GRAYLOG_USER;
const GRAYLOG_PASS = process.env.GRAYLOG_PASS;
const GRAYLOG_BASE = process.env.GRAYLOG_BASE;
const STREAM_ID = process.env.FIM_STREAM_ID;

const from = "2025-07-21T00:00:00.000Z";
const to = "2025-07-21T23:59:59.999Z";

async function fetchLogs() {
  const url = `${GRAYLOG_BASE}/api/search/universal/absolute`;
  const params = {
    query: "*",
    from,
    to,
    limit: 2,
    filter: `streams:${STREAM_ID}`,
  };

  try {
    const res = await axios.get(url, {
      params,
      auth: { username: GRAYLOG_USER, password: GRAYLOG_PASS },
      headers: { Accept: "application/json" },
    });

    console.log(chalk.green('✅ Fetched logs:'));
    console.dir(res.data.messages, { depth: 2 });

  } catch (err) {
    console.error(chalk.red("❌ Failed to fetch logs:"), err.message);
  }
}

fetchLogs();
