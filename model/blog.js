const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');

const Schema = mongoose.Schema;

blogSchema = new Schema({

   userId: {type: String , required : true , unique: true},
   heading: {type: String , required : true},
   body: {type: String , required : true}

});

blogSchema.plugin(uniqueValidator);

module.exports = mongoose.model('Blog',blogSchema);