const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const mongoose = require('mongoose');
const HttpError = require('./utils/http-error');
const adminRoute = require('./routes/adminRoute');
const userRoute = require('./routes/userRoute');
const dotenv = require('dotenv')
const port = 3000;

app.use(bodyParser.json());

app.use("/api/v1/user" , userRoute);
app.use("/api/v2/admin" , adminRoute);

app.use((req,res,next) => {
    const error = new HttpError("Page Not Found",404);
    throw error;
});

app.use((error,req,res,next) => {
    res.status(error.code);
    res.json({message: error.message || "Unknown Erroe Occured" , code: error.code});
});

dotenv.config();
mongoose.connect(`mongodb+srv://${process.env.DB_HOST}:${process.env.DB_PASSWORD}@cluster0.wfcr8.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`,
    
     {
         useUnifiedTopology: true,
         useNewUrlParser: true
     }).then(() => {
         app.listen(port , ()=> {
         console.log("server started");
          });

     }).catch(err => {

        console.log(err);
     });
