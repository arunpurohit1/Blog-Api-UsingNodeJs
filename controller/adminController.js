const HttpError = require("../utils/http-error");
const bcrypt = require("bcryptjs");
const Admin = require("../model/admin");
const User = require("../model/user");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const dotenv = require("dotenv");
dotenv.config();
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// const mailgun = require('mailgun-js');
const nodemailer = require("nodemailer");
const user = require("../model/user");
// const DOMAIN = 'sandbox608e0ad267c3481ab9aa0f2fdda1e0da.mailgun.org';
// const mg = mailgun({apiKey:process.env.API, domain: DOMAIN});

const adminSignup = async (req, res, next) => {
  const { firstName, lastName, email, password, role, adminKey } = req.body;

  let existingAdmin;
  try {
    existingAdmin = await Admin.findOne({ email: email });
  } catch (err) {
    const error = new HttpError("SignUp Failed", 500);
    return next(error);
  }

  if (existingAdmin) {
    const error = new HttpError("Admin Already Exists", 422);
    return next(error);
  }
  let encyptPassword;
  if (adminKey == `${process.env.DB_ADMINSIGNUPKEY}`) {
    try {
      encyptPassword = await bcrypt.hash(password, 12);
    } catch (err) {
      const error = new HttpError("Encryption Failed", 500);
      return next(error);
    }
  } else {
    const error = new HttpError("Admin Key Is not Valid", 500);
    return next(error);
  }

  // let encyptPassword

  //  try{
  //       encyptPassword = await bcrypt.hash(password , 12)

  //  }catch(err){
  //       const error = new HttpError('Encryption Failed' , 500);
  //       return next(error);
  //  }

  const createAdmin = new Admin({
    firstName: firstName,
    lastName: lastName,
    email: email,
    password: encyptPassword,
    role: "Admin",
  });
  try {
    await createAdmin.save();
  } catch (err) {
    const error = new HttpError("Sign Up Failed ", 500);
    return next(error);
  }

  let token;

  try {
    token = jwt.sign(
      {
        adminId: createAdmin.id,
        email: createAdmin.email,
      },
      `${process.env.DB_ADMINKEY}`,
      { expiresIn: "2h" }
    );
  } catch (err) {
    const error = new HttpError("Sign Up Failed", 403);
    return next(error);
  }
  return res
    .status(200)
    .json({ adminId: createAdmin.id, email: createAdmin.email, token: token });
};

const adminLogin = async (req, res, next) => {
  const { email, password } = req.body;

  let existingAdmin;
  try {
    existingAdmin = await Admin.findOne({ email: email });
  } catch (err) {
    const error = new HttpError("Login Failed", 500);
    return next(error);
  }

  if (!existingAdmin) {
    const error = new HttpError("Invalid Credentials", 403);
    return next(error);
  }

  let checkPassword = false;
  try {
    checkPassword = await bcrypt.compare(password, existingAdmin.password);
  } catch (err) {
    const error = new HttpError("Invalid Credentials", 403);
    return next(error);
  }

  let token;

  try {
    token = jwt.sign(
      {
        adminId: existingAdmin.id,
        email: existingAdmin.email,
      },
      `${process.env.DB_ADMINKEY}`,
      { expiresIn: "1d" }
    );
  } catch (err) {
    const error = new HttpError("Sign Up Failed", 403);
    return next(error);
  }

  res.status(200).json({ Admin: existingAdmin.email, token: token });
};


const resetPassword = async (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
    }
    const token = buffer.toString("hex");
    Admin.findOne({ email: req.body.email }).then((admin) => {
      if (!admin) {
        return res
          .status(422)
          .json({ error: "Admin Does Not Exist With this email" });
      }
      admin.resetToken = token;
      admin.expireToken = Date.now() + 36000000;
      admin.save().then((result) => {
        const msg = {
        to: `${admin.email}`, // Change to your recipient
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
            return res.status(200).json({ message: "The Email Has been Sent" });
          })
          .catch((err) => {
            const error = new HttpError("Something Went Wrong", 500);
            return next(error);
          });
      }).catch(err => {
          const error = new HttpError("Email Sent Failed Try Again", 500);
          return next(error);
      })
    });
  });
   
   
};

const forgetPassword = async (req , res , next) => {
    
    const newPassword = req.body.password
    const sentToken = req.body.token
    Admin.findOne({resetToken: sentToken , expireToken:{$gt:Date.now()}})
    .then(admin => {
      if(!admin){
        return res.status(422).json({error : "try again session expired"})
      }
      bcrypt.hash(newPassword , 12).then(hashedPassword =>{
        admin.password = hashedPassword
        admin.resetToken = undefined
        admin.expireToken = undefined
        admin.save().then((savedadmin) => {
          return res.status(200).json({message : "Password Updated Successfully"})
        })
      })
    }).catch(err => {
       console.log(err);
       const error = new HttpError("Password Update Failed", 500);
       return next(error);
    })
}
const deleteUser = async (req, res, next) => {
  const { email } = req.body;
  let existingUser;
  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError("User Deletion Failed", 500);
    return next(error);
  }

  if (existingUser) {
    return User.deleteOne({ email: email })
      .then(() => {
        res.status(200).json({ message: "User Deleted" });
      })
      .catch((err) => {
        const error = new HttpError("User Already Deleted", 500);
        return next(error);
      });
  }

  if (!existingUser) {
    return res.status(200).json({ "User Does Not Exist": 500 });
  }
};

exports.adminSignup = adminSignup;
exports.adminLogin = adminLogin;
exports.deleteUser = deleteUser;
exports.resetPassword = resetPassword;
exports.forgetPassword = forgetPassword