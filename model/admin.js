const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');

const Schema = mongoose.Schema;

adminSchema = new Schema({

    firstName: {type: String, required: true },
    lastName: {type: String, required: true },
    email: {type: String, required: true , unique: true},
    password: {type: String, required: true, minlength: 6},
    role: {type: String, required: true},
    adminKey: {type: String, required: true}

});

adminSchema.plugin(uniqueValidator);

module.exports = mongoose.model('Admin',adminSchema);