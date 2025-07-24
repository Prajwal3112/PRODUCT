const { Kafka } = require('kafkajs');
const kafka = new Kafka({
  clientId: 'backend-client',
  brokers: [process.env.KAFKA_BROKER],
});
const admin = kafka.admin();

module.exports = admin;
