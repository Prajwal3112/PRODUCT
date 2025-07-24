require('dotenv').config();
console.log('Broker from env:', process.env.KAFKA_BROKER);
const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'test-client',
  brokers: [process.env.KAFKA_BROKER],
});

const admin = kafka.admin();

(async () => {
  try {
    await admin.connect();
    const topics = await admin.listTopics();
    console.log('✅ Kafka Connected! Topics:', topics);
    await admin.disconnect();
  } catch (err) {
    console.error('❌ Kafka connection failed!', err.message);
  }
})();
