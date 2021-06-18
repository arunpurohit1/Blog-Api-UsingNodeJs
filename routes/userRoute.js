const express = require('express');
const userController = require('../controller/userController');
const checkAuth = require('../middleware/check-auth');
const route = express.Router();

route.post('/signup', userController.userSignup );
route.post('/login' , userController.userLogin);

route.use(checkAuth)
route.get('/getUser' , userController.getInfo);
route.post('/postBlog' , userController.postBlog);
route.get('/getBlog' , userController.getBlog);

module.exports = route;