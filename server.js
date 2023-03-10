const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_LINK = process.env.DATABASE_LINK;

mongoose.connect(DATABASE_LINK, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

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

        return res.json({ status: 'ok', data: token })
    }

    res.status(400).json({ status: 'error', error: 'Invalid username or email/password combination' })
})

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