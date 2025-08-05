require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const kafkaClient = require('./kafkaClient');
const opensearchClient = require('./opensearchClient');

app.get('/health', async (req, res) => {
  try {
    await kafkaClient.connect();
    const topics = await kafkaClient.listTopics();
    await kafkaClient.disconnect();

    const osHealth = await opensearchClient.cluster.health();

    res.json({ kafka: topics, opensearch: osHealth.body.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const parseDQLQuery = (dqlString) => {
  if (!dqlString || !dqlString.trim()) {
    return { match_all: {} };
  }

  const query = { bool: { must: [], should: [], must_not: [] } };
  
  // Split by AND/OR while preserving the operators
  const tokens = dqlString.split(/\s+(AND|OR|NOT)\s+/i);
  let currentOperator = 'AND';
  
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i].trim();
    
    if (['AND', 'OR', 'NOT'].includes(token.toUpperCase())) {
      currentOperator = token.toUpperCase();
      continue;
    }
    
    if (!token) continue;
    
    // Parse field:value patterns
    const fieldValueMatch = token.match(/^(\w+):\s*(.+)$/);
    if (fieldValueMatch) {
      const [, field, value] = fieldValueMatch;
      const cleanValue = value.replace(/^["']|["']$/g, ''); // Remove quotes
      
      const termQuery = {
        [cleanValue.includes('*') ? 'wildcard' : 'term']: {
          [field.includes('_id') ? field : `${field}.keyword`]: cleanValue
        }
      };
      
      if (currentOperator === 'NOT') {
        query.bool.must_not.push(termQuery);
      } else if (currentOperator === 'OR') {
        query.bool.should.push(termQuery);
      } else {
        query.bool.must.push(termQuery);
      }
    } else {
      // Free text search across all fields
      const textQuery = {
        multi_match: {
          query: token.replace(/^["']|["']$/g, ''),
          fields: ['message', 'message.message', '*'],
          type: 'best_fields',
          fuzziness: 'AUTO'
        }
      };
      
      if (currentOperator === 'NOT') {
        query.bool.must_not.push(textQuery);
      } else if (currentOperator === 'OR') {
        query.bool.should.push(textQuery);
      } else {
        query.bool.must.push(textQuery);
      }
    }
  }
  
  // If we have should clauses, set minimum_should_match
  if (query.bool.should.length > 0 && query.bool.must.length === 0) {
    query.bool.minimum_should_match = 1;
  }
  
  return query;
};

// GET /api/logs - Fetch logs from OpenSearch logs-* indices
app.get('/api/logs', async (req, res) => {
  try {
    const {
      stream = 'all',
      time = '1h',
      dql = '',
      page = 1,
      size = 50
    } = req.query;

    // Calculate time range
    const getTimeRange = (timeStr) => {
      const now = new Date();
      const timeMap = {
        '15m': 15 * 60 * 1000,
        '1h': 60 * 60 * 1000,
        '4h': 4 * 60 * 60 * 1000,
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000
      };
      return new Date(now.getTime() - (timeMap[timeStr] || timeMap['1h']));
    };

    const fromTime = getTimeRange(time);
    const from = (parseInt(page) - 1) * parseInt(size);

    // Map frontend stream names to actual OpenSearch indices
    const streamToIndexMap = {
      'all': 'logs-*',
      'authentication-logs': 'logs-authentication-*',
      'fim': 'logs-fim-*',
      'firewall': 'logs-firewall-*',
      'malware-detection': 'logs-malware-*',
      'network-logs': 'logs-network-*',
      'syslog-logs': 'logs-syslog-*',
      'vulnerability': 'logs-vulnerability-*',
      'windows-event-logs': 'logs-windows-*'
    };

    // Get the target index pattern
    const targetIndex = streamToIndexMap[stream] || 'logs-*';

    // Parse DQL query
    const dqlQuery = parseDQLQuery(dql);

    // Build complete OpenSearch query
    const query = {
      bool: {
        must: [dqlQuery],
        filter: [
          {
            range: {
              '@timestamp': {
                gte: fromTime.toISOString()
              }
            }
          }
        ]
      }
    };

    // Execute search on specific index pattern
    const searchParams = {
      index: targetIndex,
      body: {
        query,
        sort: [{ '@timestamp': { order: 'desc' } }],
        from,
        size: parseInt(size)
      }
    };

    console.log(`Searching in index: ${targetIndex}`);
    console.log('DQL Query:', dql);
    console.log('Parsed OpenSearch Query:', JSON.stringify(searchParams, null, 2));

    const response = await opensearchClient.search(searchParams);
    
    const logs = response.body.hits.hits.map(hit => {
      const source = hit._source;
      return {
        _id: hit._id,
        _index: hit._index,
        '@timestamp': source['@timestamp'],
        rule_description: source.message?.rule_description || source.rule_description || source.message?.message || 'No description',
        stream_type: source.stream || 'Unknown',
        ...source // Include all other fields
      };
    });

    const total = response.body.hits.total?.value || response.body.hits.total || 0;

    console.log(`Found ${logs.length} logs out of ${total} total from ${targetIndex}`);

    res.json({
      logs,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(size)),
      query: {
        dql: dql,
        parsedQuery: dqlQuery,
        targetIndex
      }
    });

  } catch (error) {
    console.error('Error fetching logs from OpenSearch:', error);
    res.status(500).json({ 
      error: 'Failed to fetch logs from OpenSearch',
      details: error.message 
    });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`✅ Backend running at http://192.168.1.67:${process.env.PORT}`);
});
