const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const session = require('express-session')
require('dotenv').config()

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_LINK = process.env.DATABASE_LINK;
const SESSION_SECRET = process.env.SESSION_SECRET

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
    }

    if(await bcrypt.compare(password, user.password)) {
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
    const { username, password: plainTextPassword, email } = req.body
    const validEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if(!username || typeof username !== 'string') {
        return res.status(400).json({ status: 'error', error: 'Invalid username' })
    }

    if(!email || !validEmailRegex.test(email)) {
        return res.status(400).json({ status: 'error', error: 'Invalid email' })
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.status(400).json({ status: 'error', error: 'Invalid password' })
    }

    if(plainTextPassword.length < 6) {
        return res.status(400).json({ status: 'error', error: 'Password should be at least 6 characters' })
    }

    const password = await bcrypt.hash(plainTextPassword, 10)

    try{
        const response = await User.create({
            username,
            password,
            email
        })
        console.log('User created successfully: ', response)
    } catch(error) {
        if (error.code === 11000) {
            //duplicate key
            return res.json({ status: 'error', error: 'Username or Email already in use' })
        }
        throw error
    }

    res.json({ status: 'ok' })
})

app.listen(8000, () => {
    console.log('Server up at 8000')
})