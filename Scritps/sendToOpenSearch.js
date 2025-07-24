require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');
const chalk = require('chalk').default;

const client = new Client({ node: process.env.OPENSEARCH_HOST });

function getIndexName(streamName) {
  const today = new Date();
  const dd = String(today.getDate()).padStart(2, '0');
  const mm = String(today.getMonth() + 1).padStart(2, '0'); // Months are 0-based
  const yyyy = today.getFullYear();
  const dateStr = `${dd}-${mm}-${yyyy}`;

  return 'logs-' + streamName.toLowerCase().replace(/\s+/g, '-') + `-${dateStr}`;
}

function cleanLogEntry(log) {
  const cleaned = { ...log };
  delete cleaned._id; // Avoid OpenSearch reserved field issue
  return cleaned;
}

async function indexLog(streamName, logEntry) {
  const log = logEntry.message || logEntry;
  const streamIndex = getIndexName(streamName); // 👈 now includes date

  const timestamp = log['@timestamp'] || new Date().toISOString();
  const safeLog = cleanLogEntry(log);

  try {
    await client.index({
      index: streamIndex,
      body: {
        ...safeLog,
        stream: streamName,
        indexed_at: new Date().toISOString(),
        '@timestamp': timestamp
      }
    });

    console.log(chalk.gray(`📝 Indexed log to [${streamIndex}]`));
  } catch (error) {
    console.error(chalk.red(`❌ OpenSearch indexing failed for [${streamIndex}]`), error.message);
  }
}

module.exports = {
  indexLog
};
