// checkISMStatus.js - Add to Scripts folder
require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

async function checkISMStatus() {
  try {
    console.log('📋 Checking ISM Policy Status...');
    
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index,docs.count,store.size,creation.date'
    });

    for (const indexInfo of indices.body) {
      const indexName = indexInfo.index;
      
      try {
        // Use correct API for OpenSearch 3.1
        const response = await osClient.transport.request({
          method: 'GET',
          path: `/_plugins/_ism/explain/${indexName}`
        });
        
        const indexData = response.body[indexName];
        const creationDate = new Date(parseInt(indexInfo['creation.date']));
        const ageInDays = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);
        
        console.log(`${indexName}:`);
        console.log(`  📅 Age: ${ageInDays.toFixed(1)} days`);
        console.log(`  📊 Size: ${indexInfo['store.size']}`);
        console.log(`  📈 Docs: ${indexInfo['docs.count']}`);
        
        if (indexData && indexData.policy_id) {
          console.log(`  🏷️  Policy: ${indexData.policy_id}`);
          console.log(`  🔄 State: ${indexData.state?.name || 'transitioning'}`);
          if (indexData.action) {
            console.log(`  ⚡ Action: ${indexData.action.name || 'none'}`);
          }
          if (indexData.failed) {
            console.log(`  ❌ Failed: ${indexData.info?.message || 'unknown error'}`);
          }
        } else {
          console.log(`  ❌ No ISM policy assigned`);
        }
        console.log('');
        
      } catch (error) {
        console.log(`${indexName}: ❌ Error checking status: ${error.message}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Error checking ISM status:', error.message);
  }
}

async function performanceTest() {
  try {
    console.log('\n⚡ Running Performance Test...');
    
    // Test query performance
    const start = Date.now();
    const searchResult = await osClient.search({
      index: 'logs-*',
      body: {
        query: { match_all: {} },
        size: 0,
        aggs: {
          streams: {
            terms: {
              field: 'stream',
              size: 20
            }
          }
        }
      },
      timeout: '30s'
    });
    
    const duration = Date.now() - start;
    console.log(`🚀 Query completed in: ${duration}ms`);
    console.log(`📊 Total documents: ${searchResult.body.hits.total.value}`);
    
    if (searchResult.body.aggregations?.streams?.buckets) {
      console.log('📈 Documents per stream:');
      searchResult.body.aggregations.streams.buckets.forEach(bucket => {
        console.log(`  ${bucket.key}: ${bucket.doc_count} docs`);
      });
    }

  } catch (error) {
    console.error('❌ Performance test failed:', error.message);
  }
}

async function checkCompression() {
  try {
    console.log('\n🗜️ Checking Index Compression...');
    
    const stats = await osClient.indices.stats({
      index: 'logs-*',
      metric: 'store'
    });
    
    Object.entries(stats.body.indices).forEach(([indexName, indexStats]) => {
      const sizeInBytes = indexStats.total.store.size_in_bytes;
      const sizeInMB = (sizeInBytes / (1024 * 1024)).toFixed(2);
      console.log(`  ${indexName}: ${sizeInMB} MB`);
    });
    
  } catch (error) {
    console.error('❌ Compression check failed:', error.message);
  }
}

// Run all checks
async function runAllChecks() {
  await checkISMStatus();
  await performanceTest();
  await checkCompression();
}

runAllChecks();