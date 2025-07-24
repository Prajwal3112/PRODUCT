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

app.listen(process.env.PORT, () => {
  console.log(`✅ Backend running at http://192.168.1.67:${process.env.PORT}`);
});
