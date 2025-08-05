// sendToKafka.js
require('dotenv').config();
const { Kafka, CompressionTypes } = require('kafkajs');
const chalk = require('chalk').default;

const kafka = new Kafka({
  clientId: process.env.KAFKA_CLIENT_ID || 'graylog-kafka-producer',
  brokers: [process.env.KAFKA_BROKER],
  retry: { retries: 5 },
});

const producer = kafka.producer({
  allowAutoTopicCreation: true,
});

async function initKafkaProducer() {
  try {
    await producer.connect();
    console.log(chalk.greenBright('🚀 Kafka Producer Connected'));
  } catch (err) {
    console.error(chalk.red('❌ Kafka connection failed'), err.message);
  }
}

/**
 * Sends logs to Kafka in a batch with compression.
 * 
 * @param {string} topic Kafka topic name
 * @param {Array} logs Array of logs (Graylog format)
 */
async function sendLogsToKafkaBatch(topic, logs) {
  if (!logs || logs.length === 0) return;

  try {
    const messages = logs.map((log) => {
      const payload = log.message || log || {};
      return {
        value: JSON.stringify(payload),
      };
    });

    await producer.send({
      topic,
      messages,
      compression: CompressionTypes.GZIP, // 💡 Transparent compression
    });

    console.log(
      chalk.yellow(`📦 Sent ${messages.length} logs to topic: ${topic}`)
    );
  } catch (err) {
    console.error(
      chalk.red(`❌ Kafka batch send failed for [${topic}]`),
      err.message
    );
  }
}

module.exports = {
  initKafkaProducer,
  sendLogsToKafkaBatch,
};
