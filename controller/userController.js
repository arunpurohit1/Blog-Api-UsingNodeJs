const HttpError = require('../utils/http-error');
const bcrypt = require('bcryptjs');
const User = require('../model/user');
const Blog = require('../model/blog');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

const userSignup = async (req, res, next) =>{
      
    const {firstName, lastName , email , password , DOB , role} = req.body;

    let existingUser
    try{
         
        existingUser = await User.findOne({email: email});

    }catch(err){
        const error = new HttpError('SignUp Failed' , 500);
        return next(error);
    }

    if(existingUser){
        const error = new HttpError('User Already Exists' , 422);
        return next(error);
    }

    let encyptPassword
     try{
          
          encyptPassword = await bcrypt.hash(password , 12)
         
     }catch(err){
          const error = new HttpError('Encryption Failed' , 500);
          return next(error);
     }

     const createUser = new User({
         firstName: firstName,
         lastName: lastName,
         email: email,
         password: encyptPassword,
         DOB: DOB,
         role: role

     });

     try{
         await createUser.save();
     }catch(err){
          const error = new HttpError('Sign Up Failed' , 500);
          return next(error);
     }
     let token;
     dotenv.config();
     try{
          token = jwt.sign(
           {
             userId: createUser.id,
             email: createUser.email
           },
            `${process.env.DB_USERKEY}`,
             {expiresIn : "2h"}
            );
         
     }catch(err){
         const error = new HttpError('Sign Up Failed' , 500);
         return next(error);
     }

     return res.status(200).json({userId: createUser.id , email: createUser.email , token: token} );
}

 
const userLogin = async (req,res,next) => {

    const {email , password} = req.body;

    let existingUser;
    try{
        existingUser = await User.findOne({email: email});
    }catch(err){
          const error = new HttpError('Login Failed' , 500);
          return next(error);
    }

    if(!existingUser){
          const error = new HttpError('Invalid Credentials' , 403);
          return next(error);
    }


    let checkPassword = false;
    try{

        checkPassword = await bcrypt.compare(password , existingUser.password);
    }catch(err){
          const error = new HttpError('Invalid Credentials' , 403);
          return next(error);
    }

      let token;
     dotenv.config();
     try{
          token = jwt.sign(
           {
             userId: existingUser.id,
             email: existingUser.email
           },
            `${process.env.DB_USERKEY}`,
             {expiresIn : "2h"}
            );
         
     }catch(err){
         const error = new HttpError('Sign Up Failed' , 500);
         return next(error);
     }

   return res.status(200).json({userId: existingUser.id , email: existingUser.email , token: token} );
     

}

const getInfo = async (req ,res , next) => {
    const {email} = req.body;
    let existingUser;
    try{
         existingUser = await User.findOne({email: email});
    }catch(err){
          const error = new HttpError('Something Went Wrong' , 500);
          return next(error);
    }

    if(!existingUser){
        return res.status(200).json({"User Does Not Exist" : 500})
    }

    if(existingUser){
        return res.status(200).json({
            "FirstName": existingUser.firstName,
            "LastName": existingUser.lastName,
            "email": existingUser.email,
            "Role": existingUser.role,
            "DateOfBirth": existingUser.DOB
        });
    }
}


let postBlog = async (req, res , next) => {
         
        const {userId , heading , body} = req.body;

       let existingId
       try {
           existingId  = await Blog.findOne({userId: userId});
       } catch (err) {
           const error = new HttpError('Something Went Wrong' , 500);
          return next(error);
       }
       if(existingId){
           return res.status(200).json("User Id Already Exist Try Different User Id");
       }
       const createBlog = new Blog({
           userId: userId,
           heading: heading,
           body: body
       });

       try{
         await createBlog.save();
         return res.status(200).json({message : "Blog Created"});
     }catch(err){
          const error = new HttpError('Something Went Wrong' , 500);
          return next(error);
     }
}

let getBlog = async (req, res , next) => {
    const {userId , heading ,body} = req.body;

    let existingBlog;
    try{
         existingBlog = await Blog.find({$or:[{heading:{'$regex':heading}}]}, (err ,result) => {
            if (err) {throw err}
            else{
                return res.status(200).json(result);
            }
    }catch (err){
         const error = new HttpError('Something Went Wrong' , 500);
          return next(error);
    }
    if(!existingBlog){
        return res.status(200).json({message :"User Blog Does Not Exist Kindly Check Again"});
    }
//     if(existingBlog){
//         return res.status(200).json({
//             "userId": existingBlog.userId,
//             "heading": existingBlog.heading,
//              "body": existingBlog.body
//         });
//     }
}

exports.userSignup = userSignup;
exports.userLogin = userLogin;
exports.getInfo = getInfo;
exports.postBlog = postBlog;
exports.getBlog = getBlog;
