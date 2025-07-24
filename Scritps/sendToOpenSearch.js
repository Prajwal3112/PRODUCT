require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');
const chalk = require('chalk').default;

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

/**
 * Converts a stream name like "Authentication Logs" to index format with date suffix
 */
const getIndexName = (streamName) => {
  const today = new Date();
  const dd = String(today.getDate()).padStart(2, '0');
  const mm = String(today.getMonth() + 1).padStart(2, '0');
  const yyyy = today.getFullYear();
  return `logs-${streamName.toLowerCase().replace(/\s+/g, '-')}-${dd}-${mm}-${yyyy}`;
};

/**
 * Bulk indexes a list of logs for a given stream
 */
async function bulkIndexLogs(streamName, logEntries = []) {
  if (!Array.isArray(logEntries) || logEntries.length === 0) return;

  const streamIndex = getIndexName(streamName);

  // Prepare bulk request body
  const body = logEntries.flatMap((entry) => {
    const log = entry.message || entry;
    const timestamp = log['@timestamp'] || new Date().toISOString();

    // Avoid OpenSearch metadata conflicts
    delete log._id;

    return [
      { index: { _index: streamIndex } },
      {
        ...log,
        stream: streamName,
        indexed_at: new Date().toISOString(),
        '@timestamp': timestamp
      }
    ];
  });

  try {
    const response = await osClient.bulk({ body });
    if (response.errors) {
      console.error(chalk.red(`❌ Bulk indexing had some errors for [${streamIndex}]`));
    } else {
      console.log(chalk.gray(`📝 Indexed ${logEntries.length} logs to [${streamIndex}]`));
    }
  } catch (error) {
    console.error(chalk.red(`❌ OpenSearch bulk indexing failed for [${streamIndex}]`), error.message);
  }
}

module.exports = {
  bulkIndexLogs
};
