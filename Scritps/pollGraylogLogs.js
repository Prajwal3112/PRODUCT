require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const chalk = require('chalk').default;
const { initKafkaProducer, sendLogToKafka } = require('./sendToKafka');
const { indexLog } = require('./sendToOpenSearch');

const {
    GRAYLOG_USER,
    GRAYLOG_PASS,
    GRAYLOG_BASE,
    LOG_FETCH_INTERVAL_MS
} = process.env;

const STREAMS = JSON.parse(fs.readFileSync('./streams.json', 'utf-8'));

// Track last fetch time per stream to avoid duplicates
const lastFetchTimes = {};
for (const streamName of Object.keys(STREAMS)) {
    lastFetchTimes[streamName] = new Date(Date.now() - 10000).toISOString(); // Start from 10s ago
}

const toTime = () => new Date().toISOString();

async function fetchLogs(streamName, streamId) {
    const url = `${GRAYLOG_BASE}/api/search/universal/absolute`;
    const currentToTime = toTime();

    const params = {
        query: "*",
        from: lastFetchTimes[streamName],
        to: currentToTime,
        limit: 10000,
        filter: `streams:${streamId}`
    };

    try {
        const res = await axios.get(url, {
            params,
            auth: { username: GRAYLOG_USER, password: GRAYLOG_PASS },
            headers: { Accept: "application/json" }
        });

        const logs = res.data.messages || [];

        if (logs.length > 0) {
            console.log(chalk.cyanBright(`📥 [${streamName}] Logs fetched: ${logs.length}`));
        }

        for (const entry of logs) {
            const topicName = streamName.replace(/\s+/g, '-'); // e.g., Authentication Logs → Authentication-Logs
            const logContent = entry.message || entry;

            // ✅ Send to Kafka
            await sendLogToKafka(topicName, logContent);

            // ✅ Index to OpenSearch
            await indexLog(streamName, entry);
        }

        // Update fetch checkpoint
        lastFetchTimes[streamName] = currentToTime;

    } catch (err) {
        console.error(chalk.red(`❌ Error fetching logs from [${streamName}]`), err.message);
        // Don't update lastFetchTimes to retry same window
    }
}


async function startPolling() {
    console.log(chalk.greenBright(`⏱️ Starting Graylog polling every ${LOG_FETCH_INTERVAL_MS}ms...`));

    await initKafkaProducer(); // Ensure Kafka is ready before polling

    setInterval(() => {
        for (const [streamName, streamId] of Object.entries(STREAMS)) {
            fetchLogs(streamName, streamId);
        }
    }, parseInt(LOG_FETCH_INTERVAL_MS));
}

startPolling();
