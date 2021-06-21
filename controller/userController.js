const HttpError = require('../utils/http-error');
const bcrypt = require('bcryptjs');
const User = require('../model/user');
const Blog = require('../model/blog');
const jwt = require('jsonwebtoken');
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const crypto = require('crypto');
const dotenv = require('dotenv');
 dotenv.config();
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
         role: "User"

     });

     try{
         await createUser.save();
     }catch(err){
          const error = new HttpError('Sign Up Failed' , 500);
          return next(error);
     }
     let token;
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

const resetPassword = async (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email }).then((user) => {
      if (!user) {
        return res
          .status(422)
          .json({ error: "User Does Not Exist With this email" });
      }
      user.resetToken = token;
      user.expireToken = Date.now() + 36000000;
      user
        .save()
        .then((result) => {
          const msg = {
            to: `${user.email}`, // Change to your recipient
            from: `${process.env.USER_EMAIL}`, // Change to your verified sender
            subject: "Sending with SendGrid is Fun",
            text: "and easy to do anywhere, even with Node.js",
            html: `<strong><h1>Reset Password Code </h1></strong><br> 
           <p>Kindly Use The Below Secret Code To Update Password </p>
            <h3>${token}</h3>
            <h2>Note: Do not Share Secret Code With Anyone Otherwise Strict Action Take Against You</h2>`,
          };
          sgMail
            .send(msg)
            .then(() => {
              return res
                .status(200)
                .json({ message: "The Email Has been Sent" });
            })
            .catch((err) => {
              const error = new HttpError("Something Went Wrong", 500);
              return next(error);
            });
        })
        .catch((err) => {
          const error = new HttpError("Email Sent Failed Try Again", 500);
          return next(error);
        });
    });
  });
};

const forgetPassword = async (req, res, next) => {
  const newPassword = req.body.password;
  const sentToken = req.body.token;
  User.findOne({ resetToken: sentToken, expireToken: { $gt: Date.now() } })
    .then((user) => {
      if (!user) {
        return res.status(422).json({ error: "try again session expired" });
      }
      bcrypt.hash(newPassword, 12).then((hashedPassword) => {
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.expireToken = undefined;
        user.save().then((saveduser) => {
          return res
            .status(200)
            .json({ message: "Password Updated Successfully" });
        });
      });
    })
    .catch((err) => {
      console.log(err);
      const error = new HttpError("Password Update Failed", 500);
      return next(error);
    });
};


const getInfo = async (req ,res , next) => {
    const {firstName , lastName , email} = req.body;
    let existingUser;
    try{
         existingUser = await User.findOne({firstName: firstName , lastName: lastName , email:email});
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
        });
    }catch (err){
         const error = new HttpError('Something Went Wrong' , 500);
          return next(error);
        
    }
    if(!existingBlog){
        return res.status(200).json({message :"User Id Does Not Exist Kindly Check Again"});
    }
    // if(existingBlog){
    //     return res.status(200).json({
    //         "userId": existingBlog.userId,
    //         "heading": existingBlog.heading,
    //          "body": existingBlog.body
    //     });
    // }
}

exports.userSignup = userSignup;
exports.userLogin = userLogin;
exports.getInfo = getInfo;
exports.postBlog = postBlog;
exports.getBlog = getBlog;
exports.resetPassword = resetPassword;
exports.forgetPassword = forgetPassword;