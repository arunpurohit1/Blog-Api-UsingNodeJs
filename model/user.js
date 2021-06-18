const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');

const Schema = mongoose.Schema;

userSchema = new Schema({

    firstName: {type: String, required: true },
    lastName: {type: String, required: true },
    email: {type: String, required: true , unique: true},
    password: {type: String, required: true , minlength: 6},
    DOB: {type: String, required: true , trim: true},
    role: {type: String, required: true}

});

userSchema.plugin(uniqueValidator);

module.exports = mongoose.model('User',userSchema);