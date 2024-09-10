const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LogSchema = new Schema({});

module.exports = mongoose.model('Logs', LogSchema);
