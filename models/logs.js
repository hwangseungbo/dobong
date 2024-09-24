const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LogSchema = new Schema({});

LogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 3 });

module.exports = mongoose.model('Logs', LogSchema);
