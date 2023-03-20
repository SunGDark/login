const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema(
    {
        email:{ type: String, required: true, unique: true, index: true },
        username:{ type: String, required: true, unique: true, index: true },
        password:{ type: String, required: true },
        verified:{ type: Boolean, required: true },
        verificationCode: { type: Number }
    }, { collection: 'users' }
)

const model = mongoose.model('UserSchema', UserSchema)

module.exports = model