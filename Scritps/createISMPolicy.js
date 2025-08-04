// createISMPolicy.js - Add this to your Scripts/ folder
require('dotenv').config();
const { Client } = require('@opensearch-project/opensearch');

const osClient = new Client({ node: process.env.OPENSEARCH_HOST });

const ismPolicy = {
  policy: {
    description: "Hot-Warm-Cold lifecycle for log indices",
    default_state: "hot",
    states: [
      {
        name: "hot",
        actions: [
          {
            replica_count: {
              number_of_replicas: 0
            }
          }
        ],
        transitions: [
          {
            state_name: "warm",
            conditions: {
              min_index_age: "5d"
            }
          }
        ]
      },
      {
        name: "warm",
        actions: [
          {
            replica_count: {
              number_of_replicas: 0
            }
          },
          {
            force_merge: {
              max_num_segments: 1
            }
          }
        ],
        transitions: [
          {
            state_name: "cold",
            conditions: {
              min_index_age: "10d"
            }
          }
        ]
      },
      {
        name: "cold",
        actions: [
          {
            replica_count: {
              number_of_replicas: 0
            }
          },
          {
            force_merge: {
              max_num_segments: 1
            }
          }
        ],
        transitions: [
          {
            state_name: "delete",
            conditions: {
              min_index_age: "60d"
            }
          }
        ]
      },
      {
        name: "delete",
        actions: [
          {
            delete: {}
          }
        ]
      }
    ],
    ism_template: [
      {
        index_patterns: ["logs-*"],
        priority: 100
      }
    ]
  }
};

async function createPolicy() {
  try {
    await osClient.ism.putPolicy({
      policy_id: 'log-lifecycle-policy',  // 🔧 Fixed: policy_id not policyId
      body: ismPolicy
    });
    console.log('✅ ISM Policy created successfully');
  } catch (error) {
    console.error('❌ Failed to create ISM policy:', error.message);
  }
}

createPolicy();