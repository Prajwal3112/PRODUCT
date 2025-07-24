require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const client = new Client({ node: process.env.OPENSEARCH_HOST });

(async () => {
  try {
    const health = await client.cluster.health();
    console.log('✅ OpenSearch Connected! Cluster status:', health.body.status);
  } catch (err) {
    console.error('❌ OpenSearch connection failed!', err.message);
  }
})();
