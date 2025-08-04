// applyISMToExisting.js - Add to Scripts folder
require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

async function applyISMPolicyToExistingIndices() {
  try {
    console.log('🔄 Applying ISM Policy to existing indices...');
    
    // 1. Get all log indices
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index,creation.date'
    });

    console.log(`Found ${indices.body.length} existing log indices`);

    // 2. Apply ISM policy to each index
    for (const indexInfo of indices.body) {
      const indexName = indexInfo.index;
      const creationDate = new Date(parseInt(indexInfo['creation.date']));
      const ageInDays = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);
      
      console.log(`Processing: ${indexName} (${ageInDays.toFixed(1)} days old)`);
      
      try {
        // Apply ISM policy
        await osClient.ism.addPolicy({
          index: indexName,
          body: {
            policy_id: 'log-lifecycle-policy'
          }
        });
        
        // Determine which state it should be in based on age
        let targetState = 'hot';
        if (ageInDays > 10) targetState = 'cold';
        else if (ageInDays > 2) targetState = 'warm';
        
        // Move to appropriate state if not hot
        if (targetState !== 'hot') {
          await osClient.ism.changePolicy({
            index: indexName,
            body: {
              policy_id: 'log-lifecycle-policy',
              state: targetState
            }
          });
          console.log(`  ✅ Applied policy and moved to ${targetState} state`);
        } else {
          console.log(`  ✅ Applied policy (hot state)`);
        }
        
      } catch (error) {
        console.log(`  ❌ Failed to apply policy: ${error.message}`);
      }
    }
    
    console.log('\n🎉 ISM Policy application completed!');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

async function checkISMStatus() {
  try {
    console.log('\n📊 Checking ISM Policy Status...');
    
    const indices = await osClient.cat.indices({
      index: 'logs-*',
      format: 'json',
      h: 'index,docs.count,store.size,creation.date'
    });

    for (const indexInfo of indices.body) {
      const indexName = indexInfo.index;
      
      try {
        // Check ISM status using the correct API
        const response = await osClient.transport.request({
          method: 'GET',
          path: `/_plugins/_ism/explain/${indexName}`
        });
        
        const indexData = response.body[indexName];
        if (indexData && indexData.policy_id) {
          const creationDate = new Date(parseInt(indexInfo['creation.date']));
          const ageInDays = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);
          
          console.log(`${indexName}:`);
          console.log(`  📅 Age: ${ageInDays.toFixed(1)} days`);
          console.log(`  📊 Size: ${indexInfo['store.size']}`);
          console.log(`  🏷️  Policy: ${indexData.policy_id}`);
          console.log(`  🔄 State: ${indexData.state || 'unknown'}`);
          console.log('');
        } else {
          console.log(`${indexName}: ❌ No ISM policy assigned`);
        }
        
      } catch (error) {
        console.log(`${indexName}: ❌ Error checking status`);
      }
    }
    
  } catch (error) {
    console.error('❌ Error checking ISM status:', error.message);
  }
}

// Run both functions
async function main() {
  await applyISMPolicyToExistingIndices();
  await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
  await checkISMStatus();
}

main();