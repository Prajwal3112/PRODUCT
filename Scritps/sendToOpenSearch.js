require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');
const chalk = require('chalk').default;

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

const getIndexName = (streamName) => {
  const today = new Date();
  const dd = String(today.getDate()).padStart(2, '0');
  const mm = String(today.getMonth() + 1).padStart(2, '0');
  const yyyy = today.getFullYear();
  return `logs-${streamName.toLowerCase().replace(/\s+/g, '-')}-${dd}-${mm}-${yyyy}`;
};

// 🔧 Index template with compression settings
const indexTemplate = {
  index_patterns: ["logs-*"],
  template: {
    settings: {
      number_of_shards: 1,
      number_of_replicas: 0,
      "index.codec": "best_compression", // 🔥 Enable compression
      "index.refresh_interval": "30s",
      "index.translog.flush_threshold_size": "1gb",
      "index.merge.scheduler.max_thread_count": 1
    },
    mappings: {
      properties: {
        "@timestamp": { type: "date" },
        message: { type: "text", analyzer: "standard" },
        stream: { type: "keyword" },
        indexed_at: { type: "date" }
      }
    }
  },
  priority: 500
};

// 🔧 Ensure index template exists
async function ensureIndexTemplate() {
  try {
    await osClient.indices.putIndexTemplate({
      name: 'logs-template',
      body: indexTemplate
    });
    console.log(chalk.blue('📋 Index template updated'));
  } catch (error) {
    console.error(chalk.red('❌ Failed to create index template:'), error.message);
  }
}

async function bulkIndexLogs(streamName, logEntries = []) {
  if (!Array.isArray(logEntries) || logEntries.length === 0) return;

  await ensureIndexTemplate(); // 🔧 Ensure template exists

  const streamIndex = getIndexName(streamName);
  const body = logEntries.flatMap((entry) => {
    const log = entry.message || entry;
    const timestamp = log['@timestamp'] || new Date().toISOString();
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
    const response = await osClient.bulk({ 
      body,
      timeout: '30s',
      refresh: false // 🔧 Don't refresh immediately
    });
    
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