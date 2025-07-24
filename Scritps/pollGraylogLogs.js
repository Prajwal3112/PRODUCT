require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const chalk = require('chalk').default;
const { initKafkaProducer, sendLogsToKafkaBatch } = require('./sendToKafka');
const { bulkIndexLogs } = require('./sendToOpenSearch');

const {
    GRAYLOG_USER,
    GRAYLOG_PASS,
    GRAYLOG_BASE,
    LOG_FETCH_INTERVAL_MS
} = process.env;

const STREAMS = JSON.parse(fs.readFileSync('./streams.json', 'utf-8'));
const lastFetchTimes = {};

// Initialize checkpoints 10s ago
for (const streamName of Object.keys(STREAMS)) {
    lastFetchTimes[streamName] = new Date(Date.now() - 10000).toISOString();
}

const toTime = () => new Date().toISOString();

/**
 * Fetch logs for one stream
 */
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

    const logStart = Date.now();
    console.log(chalk.blue(`[${streamName}] ⏳ Fetching logs from ${lastFetchTimes[streamName]} → ${currentToTime}`));

    try {
        const res = await axios.get(url, {
            params,
            timeout: 10000, // 🔒 10s timeout in case Graylog is unresponsive
            auth: { username: GRAYLOG_USER, password: GRAYLOG_PASS },
            headers: { Accept: "application/json" }
        });

        const logs = res.data.messages || [];
        const topicName = streamName.replace(/\s+/g, '-');

        if (logs.length > 0) {
            console.log(chalk.cyanBright(`📥 [${streamName}] Logs fetched: ${logs.length}`));
            await sendLogsToKafkaBatch(topicName, logs);
            await bulkIndexLogs(streamName, logs);
        }

        lastFetchTimes[streamName] = currentToTime;

        console.log(chalk.green(`[${streamName}] ✅ Fetch cycle done in ${Date.now() - logStart}ms`));

    } catch (err) {
        console.error(chalk.red(`❌ [${streamName}] Error during fetch: ${err.message}`));
    }
}

let loopCount = 0;

async function startPolling() {
    console.log(chalk.greenBright(`⏱️ Starting Graylog polling every ${LOG_FETCH_INTERVAL_MS}ms...`));
    await initKafkaProducer();

    // 🔁 Log script heartbeat every 30 seconds
    setInterval(() => {
        console.log(chalk.yellow(`💡 [Heartbeat] Script alive. Cycle: ${loopCount}`));
    }, 30000);

    // 🔁 Main fetch loop
    setInterval(() => {
        loopCount++;
        for (const [streamName, streamId] of Object.entries(STREAMS)) {
            fetchLogs(streamName, streamId);
        }
    }, parseInt(LOG_FETCH_INTERVAL_MS));
}

startPolling();
