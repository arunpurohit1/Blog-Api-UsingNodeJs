const HttpError = require('../utils/http-error');
const bcrypt = require('bcryptjs');
const Admin = require('../model/admin');
const User = require('../model/user');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const SendOtp = require('sendotp');
dotenv.config();
const adminSignup = async (req, res, next) =>{
      
    const {firstName, lastName , email , password , role , adminKey} = req.body;

    let existingAdmin;
    try{
         
        existingAdmin = await Admin.findOne({email: email});

    }catch(err){
        const error = new HttpError('SignUp Failed' , 500);
        return next(error);
    }

    if(existingAdmin){
        const error = new HttpError('Admin Already Exists' , 422);
        return next(error);
    }
    if(adminKey == `${process.env.DB_ADMINSIGNUPKEY}`){
        try{
            console.log("Admin Key is Valid")
        }
        catch(err){
            const error = new HttpError('Signup Failed' , 500);
            return next(error);
        }
    }
    else{
        const error = new HttpError('Invalid Admin Key' , 403);
        return next(error);
    }

    let encyptPassword
     try{
          
          encyptPassword = await bcrypt.hash(password , 12)
         
     }catch(err){
          const error = new HttpError('Encryption Failed' , 500);
          return next(error);
     }

      const createAdmin = new Admin({
         firstName: firstName,
         lastName: lastName,
         email: email,
         password: encyptPassword,
         role: role,
         adminKey: "secureAdminKey"
     });
     try{
         await createAdmin.save();
     }catch(err){
          const error = new HttpError('Sign Up Failed ' , 500);
          return next(error);
     }
    
    let token;
    
    try{
           token = jwt.sign(
           {
             adminId: createAdmin.id,
             email: createAdmin.email
           },
            `${process.env.DB_ADMINKEY}`,
             {expiresIn : "2h"}
            );
     }catch(err){
         const error = new HttpError('Sign Up Failed' , 403);
         return next(error);
     }
     return res.status(200).json({adminId: createAdmin.id , email: createAdmin.email, token: token });
}

 
const adminLogin = async (req,res,next) => {

    const {email , password} = req.body;

    let existingAdmin;
    try{
        existingAdmin = await Admin.findOne({email: email});
    }catch(err){
          const error = new HttpError('Login Failed' , 500);
          return next(error);
    }

    if(!existingAdmin){
          const error = new HttpError('Invalid Credentials' , 403);
          return next(error);
    }


    let checkPassword = false;
    try{

        checkPassword = await bcrypt.compare(password , existingAdmin.password);
    }catch(err){
          const error = new HttpError('Invalid Credentials' , 403);
          return next(error);
    }
    
    let token;
    
    try{
           token = jwt.sign(
           {
             adminId: existingAdmin.id,
             email: existingAdmin.email
           },
            `${process.env.DB_ADMINKEY}`,
             {expiresIn : "2h"}
            );
     }catch(err){
         const error = new HttpError('Sign Up Failed' , 403);
         return next(error);
     }

     res.status(200).json(
         {'Admin': existingAdmin.email,
          token: token,
         });

}


const deleteUser = async (req  ,res , next) =>{

    const {email} = req.body
    let existingUser;
    try{
         existingUser = await User.findOne({email: email});
    }catch(err){
          const error = new HttpError('User Deletion Failed' , 500);
          return next(error);
    }

     if(existingUser){
        return User.deleteOne({email: email}).then(() =>{
            res.status(200).json({message : "User Deleted"})
        }).catch(err => {
             const error = new HttpError('User Already Deleted' , 500);
             return next(error);
        })    
    }

    if(!existingUser){
        return res.status(200).json({"User Does Not Exist" : 500})
    }

   
    
}




exports.adminSignup = adminSignup;
exports.adminLogin = adminLogin;
exports.deleteUser = deleteUser;