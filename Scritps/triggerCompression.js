// triggerCompression.js - Manually trigger compression for existing indices
require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

async function manuallyCompressIndices() {
  try {
    console.log('🔄 Starting manual compression for indices...');
    
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index,store.size,docs.count,creation.date'
    });

    for (const indexInfo of indices.body) {
      const indexName = indexInfo.index;
      const sizeInMB = parseFloat(indexInfo['store.size'].replace(/[^\d.]/g, ''));
      const creationDate = new Date(parseInt(indexInfo['creation.date']));
      const ageInDays = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);
      
      // Only compress indices older than 2 days or larger than 10MB
      if (ageInDays > 2 || sizeInMB > 10) {
        console.log(`\n🗜️ Compressing: ${indexName} (${indexInfo['store.size']}, ${ageInDays.toFixed(1)} days old)`);
        
        try {
          // Step 1: Close index for settings update
          console.log(`  📝 Updating compression settings...`);
          await osClient.indices.close({ index: indexName });
          
          // Step 2: Apply best compression
          await osClient.indices.putSettings({
            index: indexName,
            body: {
              settings: {
                "index.codec": "best_compression",
                "index.refresh_interval": "30s"
              }
            }
          });
          
          // Step 3: Reopen index
          await osClient.indices.open({ index: indexName });
          
          // Step 4: Force merge to 1 segment with compression
          console.log(`  🔧 Force merging with compression...`);
          const mergeResponse = await osClient.indices.forcemerge({
            index: indexName,
            max_num_segments: 1,
            wait_for_completion: false // Don't wait as it can take time
          });
          
          console.log(`  ✅ Compression triggered successfully`);
          
        } catch (error) {
          console.log(`  ❌ Failed to compress: ${error.message}`);
        }
        
        // Small delay between indices
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        console.log(`⏭️ Skipping ${indexName} (${indexInfo['store.size']}, ${ageInDays.toFixed(1)} days old)`);
      }
    }
    
    console.log('\n🎉 Manual compression completed!');
    console.log('💡 Note: Compression happens in background. Check sizes in 5-10 minutes.');
    
  } catch (error) {
    console.error('❌ Error during manual compression:', error.message);
  }
}

async function checkCompressionProgress() {
  try {
    console.log('\n📊 Checking compression progress...');
    
    // Check for ongoing merge operations
    const tasks = await osClient.tasks.list({
      actions: '*forcemerge*',
      detailed: true
    });
    
    if (tasks.body.nodes && Object.keys(tasks.body.nodes).length > 0) {
      console.log('🔄 Active compression tasks:');
      Object.values(tasks.body.nodes).forEach(node => {
        Object.values(node.tasks || {}).forEach(task => {
          console.log(`  ${task.description} - ${task.status?.percent_complete || 0}% complete`);
        });
      });
    } else {
      console.log('✅ No active compression tasks');
    }
    
    // Show current index sizes
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index,store.size,docs.count',
      s: 'store.size:desc'
    });
    
    console.log('\n📈 Current index sizes (largest first):');
    indices.body.slice(0, 10).forEach(idx => {
      console.log(`  ${idx.index}: ${idx['store.size']} (${idx['docs.count']} docs)`);
    });
    
  } catch (error) {
    console.error('❌ Error checking progress:', error.message);
  }
}

// Main execution
async function main() {
  console.log('🚀 Manual Index Compression Tool\n');
  
  await manuallyCompressIndices();
  await new Promise(resolve => setTimeout(resolve, 2000));
  await checkCompressionProgress();
}

main();