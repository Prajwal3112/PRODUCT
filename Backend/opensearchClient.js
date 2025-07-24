const { Client } = require('@opensearch-project/opensearch');
const client = new Client({ node: process.env.OPENSEARCH_HOST });
module.exports = client;
