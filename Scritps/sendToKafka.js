// sendToKafka.js
require('dotenv').config();
const { Kafka } = require('kafkajs');
const chalk = require('chalk').default;

const kafka = new Kafka({
  clientId: process.env.KAFKA_CLIENT_ID || 'graylog-kafka-producer',
  brokers: [process.env.KAFKA_BROKER]
});

const producer = kafka.producer();

async function initKafkaProducer() {
  await producer.connect();
  console.log(chalk.greenBright('🚀 Kafka Producer Connected'));
}

// ✅ Send an array of logs to a topic in one batch
async function sendLogsToKafkaBatch(topic, logs) {
  if (!logs || logs.length === 0) return;

  try {
    const messages = logs.map((log) => ({
      value: JSON.stringify(log.message || log)
    }));

    await producer.send({
      topic,
      messages
    });

    console.log(chalk.yellow(`📦 Sent ${messages.length} logs to topic: ${topic}`));
  } catch (err) {
    console.error(chalk.red(`❌ Kafka batch send failed for [${topic}]`), err.message);
  }
}

module.exports = {
  initKafkaProducer,
  sendLogsToKafkaBatch
};
