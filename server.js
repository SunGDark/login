const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const UserVerification = require('./model/UserVerification')
//const UserOTPVerification = require('./model/UserOTPVerification')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const session = require('express-session')
const nodemailer = require('nodemailer')
// unique string version 4
const {v4: uuidv4} = require('uuid')
require('dotenv').config()
//cors
//const cors = require("cors");
//app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_LINK = process.env.DATABASE_LINK;
const SESSION_SECRET = process.env.SESSION_SECRET;
const AUTH_EMAIL = process.env.AUTH_EMAIL;
const AUTH_PASS = process.env.AUTH_PASS;
const PORT = process.env.PORT;

const port = PORT || 8000

mongoose.connect(DATABASE_LINK, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const app = express()

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}))

app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

// Check if user is logged in
const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).send("Not logged in");
    }
};

//Send verification email to user
const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false,
    auth: {
        user: AUTH_EMAIL,
        pass: AUTH_PASS
    }
});

 // testing success
 transporter.verify((error, success) => {
    if(error) {
        console.log(error);
    } else {
        console.log("Ready for messages");
        console.log(success);
    }
})

// Display the username of the logged-in user
app.get('/api/user', isLoggedIn, (req, res) => {
    res.send(req.session.user.username);
});

// Log out the user
app.post('/api/logout', isLoggedIn, (req, res) => {
    req.session.destroy();
    res.send("Logged out successfully");
});

app.post('/api/change-password', async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body

    if(!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    if(plainTextPassword.length < 6) {
        return res.json({ status: 'error', error: 'Password should be at least 6 characters' })
    }

    try{
        const user = jwt.verify(token, JWT_SECRET)
        // ...
        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)

        await User.updateOne(
            { _id }, 
            {
                $set: { password }
            }
        )
        res.json({ status: 'ok' })
    } catch(error) {
        res.json({ status: 'error', error: ';))' })
    }
})

app.post('/api/login', async (req, res) => {
    const usernameOrEmail = req.body.usernameOrEmail;
    const password = req.body.password;
    console.log(usernameOrEmail);
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] }).lean()
    console.log(user);
    if (!user) {
        return res.status(400).json({ status: 'error', error: 'Invalid username or email/password combination' })
    } else if (!user.verified) {
        return res.status(400).json({ status: 'error', error: "Email hasn't been verified yet. Check your inbox.",
        });
    } else if(await bcrypt.compare(password, user.password)) {
        // the username, password combination is successful

        const token = jwt.sign(
            { 
                id: user._id, 
                username: user.username,
                email: user.email 
            }, 
            JWT_SECRET
        )

        // set the cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 3600000 // 1 hour
        })
        
        req.session.user = {id: user._id, username: user.username, email: user.email };
        res.json({ status: 'ok', data: token })
        
    } else{
        res.status(400).json({ status: 'error', error: 'Invalid username or email/password combination' })
    }

    
})

// redirect to welcome page
app.get('/welcome.html', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login.html');
    }

    try {
        const decodedToken = jwt.verify(token, JWT_SECRET);
        res.render('welcome', { username: decodedToken.username });
    } catch (err) {
        console.error(err);
        res.redirect('/login.html');
    }
});

app.post('/api/register', async (req, res) => {
    let { username, password: plainTextPassword, email } = req.body;
    const validEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const password = await bcrypt.hash(plainTextPassword, 10);
    username = username.trim();
    email = email.trim();
    plainTextPassword = plainTextPassword.trim();
  
    if (!username || typeof username !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Invalid username' 
    });
    } else if (!email || !validEmailRegex.test(email)) {
      return res.status(400).json({ status: 'error', error: 'Invalid email' 
    });
    } else if (!plainTextPassword || typeof plainTextPassword !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Invalid password' 
    });
    } else if (plainTextPassword.length < 6) {
      return res.status(400).json({ status: 'error', error: 'Password should be at least 6 characters' 
    });
    } else {
      // Checking if user already exists
      User.find({ email })
        .then((result) => {
          if (result.length) {
            // A user already exists
            res.json({
              status: 'FAILED',
              message: 'User with the provided email already exists',
            });
          } else {
            const newUser = new User({
              username,
              email,
              password,
              verified: false,
            });
  
            newUser
              .save()
              .then((result) => {
                // handle account verification
                sendVerificationEmail(result, res);
              })
              .catch((err) => {
                res.json({
                  status: 'FAILED',
                  message: 'An error occurred while saving user account!',
                });
              });
          }
        })
        .catch((err) => {
          console.log(err);
          res.json({
            status: 'FAILED',
            message: 'An error occurred while checking for existing user!',
          });
        });
    }
}); 

// send verification email
const sendVerificationEmail = ({ _id, email }, res) => {
    // url to be used in the email
    const currentUrl = "http://localhost:8000/";
  
    const uniqueString = uuidv4() + _id;
  
    // mail options
    const mailOptions = {
      from: AUTH_EMAIL,
      to: email,
      subject: "Verify Your Email",
      html: `<p>Verify your email address to complete the signup and log into your account.</p><p>This link 
      <b>expires in 6 hours</b>.</p><p>Press <a href=${currentUrl + "user/verify/" + _id + "/" + uniqueString
      }>here</a> to proceed.</p>`,
    };
  
    // hash the uniqueString
    const saltRounds = 10;
    bcrypt
      .hash(uniqueString, saltRounds)
      .then((hashedUniqueString) => {
        // set values in userVerification collection
        const newVerification = new UserVerification({
          userId: _id,
          uniqueString: hashedUniqueString,
          createdAt: Date.now(),
          expiresAt: Date.now() + 21600000,
        });
  
        newVerification
          .save()
          .then(() => {
            transporter
              .sendMail(mailOptions)
              .then(() => {
                // email sent and verification record saved
                res.json({
                  status: "PENDING",
                  message: "Verification email sent",
                });
              })
              .catch((error) => {
                console.log(error);
                res.json({
                  status: "FAILED",
                  message: "Verification email failed",
                });
              });
          })
          .catch((error) => {
            console.log(error);
            res.json({
              status: "FAILED",
              message: "Couldn't save verification email data!",
            });
          });
      })
      .catch(() => {
        res.json({
          status: "FAILED",
          message: "An error occurred while hashing email data!",
        });
    });
};

// verify email
//could have a rout issue here
app.get("/verify/:userId/:uniqueString", (req, res) => {
    let { userId, uniqueString } = req.params;
  
    UserVerification.find({ userId })
      .then((result) => {
        if (result.length > 0) {
          // user verification record exists so we proceed
  
          const { expiresAt } = result[0];
          const hashedUniqueString = result[0].uniqueString;
  
          // checking for expired unique string
          if (expiresAt < Date.now()) {
            // record has expired so we delete it
            UserVerification.deleteOne({ userId })
              .then((result) => {
                User.deleteOne({ _id: userId })
                  .then(() => {
                    let message = "Link has expired. Please sign up again.";
                    res.redirect(`/user/verified?error=true&message=${message}`);
                  })
                  .catch((error) => {
                    let message =
                      "Clearing user with expired unique string failed";
                    res.redirect(`/user/verified?error=true&message=${message}`);
                  });
              })
              .catch((error) => {
                console.log(error);
                let message =
                  "An error occurred while clearing expired user verification record";
                res.redirect(`/user/verified?error=true&message=${message}`);
              });
          } else {
            // valid record exists so we validate the user string
            // First compare the hashed unique string
  
            bcrypt
              .compare(uniqueString, hashedUniqueString)
              .then((result) => {
                if (result) {
                  // strings match
  
                  User.updateOne({ _id: userId }, { verified: true })
                    .then(() => {
                      UserVerification.deleteOne({ userId })
                        .then(() => {
                          res.sendFile(
                            path.join(__dirname, "./../views/verified.html")
                          );
                        })
                        .catch((error) => {
                          console.log(error);
                          let message =
                            "An error occurred while finalizing successful verification.";
                          res.redirect(
                            `/user/verified?error=true&message=${message}`
                          );
                        });
                    })
                    .catch((error) => {
                      console.log(error);
                      let message =
                        "An error occurred while updating user record to show verified.";
                      res.redirect(
                        `/user/verified?error=true&message=${message}`
                      );
                    });
                } else {
                  // existing record but incorrect verification details passed.
                  let message =
                    "Invalid verification details passed. Check your inbox.";
                  res.redirect(`/user/verified?error=true&message=${message}`);
                }
              })
              .catch((error) => {
                let message = "An error occurred while comparing unique strings.";
                res.redirect(`/user/verified?error=true&message=${message}`);
              });
          }
        } else {
          // user verification record doesn't exist
          let message =
            "Account record doesn't exist or has been verified already. Please sign up or log in.";
          res.redirect(`/user/verified?error=true&message=${message}`);
        }
      })
      .catch((error) => {
        console.log(error);
        let message =
          "An error occurred while checking for existing user verification record";
        res.redirect(`/user/verified?error=true&message=${message}`);
    });
});

// Verified page route
app.get("/verified", (req, res) => {
    res.sendFile(path.join(__dirname, "./../views/verified.html"));
});

//res.json({ status: 'ok' })

// res.redirect('/verification.html'); // Redirect to verification page


app.listen(port, () => {
console.log(`Server running on port ${port}`);
});