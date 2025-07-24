// sendToKafka.js
require('dotenv').config();
const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'graylog-kafka-producer',
  brokers: [process.env.KAFKA_BROKER],
});

const producer = kafka.producer();

async function initKafkaProducer() {
  await producer.connect();
}

async function sendLogToKafka(topicName, logData) {
  try {
    await producer.send({
      topic: topicName,
      messages: [{ value: JSON.stringify(logData) }],
    });
    console.log(`📦 Log sent to topic: ${topicName}`);
  } catch (error) {
    console.error(`❌ Kafka Send Error (${topicName}):`, error.message);
  }
}

module.exports = { initKafkaProducer, sendLogToKafka };
