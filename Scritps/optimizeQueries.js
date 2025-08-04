// optimizeQueriesFixed.js - Apply only dynamic settings
require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

async function applyDynamicSettings() {
  try {
    console.log('🚀 Applying dynamic OpenSearch optimizations...');

    // Apply only settings that can be changed dynamically
    await osClient.cluster.putSettings({
      body: {
        persistent: {
          // Thread pools - these are dynamic
          "thread_pool.search.size": 4,
          "thread_pool.search.queue_size": 1000,
          "thread_pool.write.size": 4,
          "thread_pool.write.queue_size": 1000,
          
          // Circuit breakers - dynamic
          "indices.breaker.total.limit": "70%",
          "indices.breaker.request.limit": "40%",
          "indices.breaker.fielddata.limit": "30%",
          
          // Search settings - dynamic
          "search.max_buckets": 100000,
          "search.default_search_timeout": "30s",
          
          // Memory settings - dynamic
          "indices.fielddata.cache.size": "20%",
          "indices.memory.index_buffer_size": "30%"
        }
      }
    });

    console.log('✅ Dynamic settings applied successfully!');
    
  } catch (error) {
    console.error('❌ Error applying dynamic settings:', error.message);
  }
}

async function updateIndexTemplate() {
  try {
    console.log('📋 Updating index template for performance...');
    
    await osClient.indices.putTemplate({
      name: 'logs-performance-template',
      body: {
        index_patterns: ['logs-*'],
        settings: {
          // These settings apply to NEW indices only
          "refresh_interval": "30s",
          "number_of_replicas": 0,
          "index.codec": "best_compression",
          "index.max_result_window": 50000,
          
          // Cache settings for new indices
          "index.queries.cache.enabled": true,
          "index.requests.cache.enable": true
        },
        mappings: {
          properties: {
            "@timestamp": { 
              type: "date",
              format: "strict_date_optional_time||epoch_millis"
            },
            "message": { 
              type: "text",
              analyzer: "standard"
            },
            "stream": { 
              type: "keyword"
            },
            "source": { type: "keyword" },
            "level": { type: "keyword" },
            "host": { type: "keyword" },
            "user": { type: "keyword" }
          }
        }
      }
    });
    
    console.log('✅ Index template updated for new indices!');
    
  } catch (error) {
    console.error('❌ Error updating index template:', error.message);
  }
}

async function applyToExistingIndices() {
  try {
    console.log('🔧 Applying performance settings to existing indices...');
    
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index'
    });

    for (const indexInfo of indices.body) {
      const indexName = indexInfo.index;
      
      try {
        // Apply settings that can be changed on existing indices
        await osClient.indices.putSettings({
          index: indexName,
          body: {
            settings: {
              "refresh_interval": "30s",
              "index.max_result_window": 50000
            }
          }
        });
        
        console.log(`  ✅ Updated settings for ${indexName}`);
        
      } catch (error) {
        console.log(`  ❌ Failed to update ${indexName}: ${error.message}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Error updating existing indices:', error.message);
  }
}

async function checkFinalSettings() {
  try {
    console.log('\n📊 Final Performance Check:');
    
    // Check cluster settings
    const settings = await osClient.cluster.getSettings();
    const persistent = settings.body.persistent;
    
    console.log('Applied Settings:');
    console.log(`  🔍 Search threads: ${persistent['thread_pool.search.size'] || 'default'}`);
    console.log(`  📦 Search queue: ${persistent['thread_pool.search.queue_size'] || 'default'}`);
    console.log(`  💾 Memory buffer: ${persistent['indices.memory.index_buffer_size'] || 'default'}`);
    console.log(`  🛡️  Total breaker: ${persistent['indices.breaker.total.limit'] || 'default'}`);
    
    // Test query performance again
    const startTime = Date.now();
    const testQuery = await osClient.search({
      index: 'logs-*',
      body: {
        query: { match_all: {} },
        size: 100,
        aggs: {
          streams: {
            terms: { field: 'stream', size: 10 }
          }
        }
      }
    });
    const queryTime = Date.now() - startTime;
    
    console.log(`\n⚡ Test query performance: ${queryTime}ms`);
    console.log(`📊 Total documents: ${testQuery.body.hits.total.value}`);
    
    if (queryTime < 300) {
      console.log('🚀 Excellent! Ready for 15+ concurrent users');
    } else if (queryTime < 600) {
      console.log('✅ Good performance for concurrent users');
    } else {
      console.log('⚠️ Consider further optimization');
    }
    
  } catch (error) {
    console.error('❌ Error checking final settings:', error.message);
  }
}

// Load testing simulation
async function simulateLoadTest() {
  try {
    console.log('\n🧪 Simulating 10 concurrent users...');
    
    const userQueries = Array.from({length: 10}, (_, i) => 
      osClient.search({
        index: 'logs-*',
        body: {
          query: {
            bool: {
              must: [
                { range: { "@timestamp": { gte: "now-24h" } } }
              ]
            }
          },
          size: 50 + (i * 10), // Vary query size
          sort: [{ "@timestamp": { order: "desc" }}]
        }
      })
    );
    
    const startTime = Date.now();
    const results = await Promise.allSettled(userQueries);
    const totalTime = Date.now() - startTime;
    
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    console.log(`📊 Load Test Results:`);
    console.log(`  ✅ Successful queries: ${successful}/10`);
    console.log(`  ❌ Failed queries: ${failed}/10`);
    console.log(`  ⏱️  Total time: ${totalTime}ms`);
    console.log(`  📈 Avg time per query: ${Math.round(totalTime/10)}ms`);
    
    if (successful >= 8 && totalTime < 3000) {
      console.log('🎉 System ready for production concurrent load!');
    }
    
  } catch (error) {
    console.error('❌ Load test error:', error.message);
  }
}

// Main execution
async function main() {
  await applyDynamicSettings();
  await updateIndexTemplate();
  await applyToExistingIndices();
  await new Promise(resolve => setTimeout(resolve, 2000));
  await checkFinalSettings();
  await simulateLoadTest();
}

main();