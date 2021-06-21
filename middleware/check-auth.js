const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const HttpError = require('../utils/http-error')

module.exports = (req , res , next) => {

     if(req.method == "OPTIONS"){
        return next();
     }
    try{
         const token = req.headers.authorization.split(" ")[1];
         if(!token){
             error = new HttpError("Invalid Token ", 403);
             return next(error)
         }
         dotenv.config();
        if(req.headers.role == "User"){

            let decodeTokenUser = jwt.verify(token ,process.env.DB_USERKEY);
            req.user = decodeTokenUser;
         }
        else if(req.headers.role == "Admin"){
             let decodeTokenAdmin = jwt.verify(token ,process.env.DB_ADMINKEY);
             req.admin = decodeTokenAdmin;
        }
        
         next();
    }catch(err){

        error = new HttpError("Authentication Failed Please Try Again Later", 403);
        return next(error)
    }
    

}