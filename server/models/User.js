const mongoose = require('mongoose')

const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true, // 이메일에서 min hwan@naver.com 일 때 스페이스를 지워줌
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0 // 0: 일반유저 1: 관리자
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: { // 토큰 유효기간
        type: Number
    }
})



//비밀번호 암호화
userSchema.pre('save', function(next){
    let user = this
    if(user.isModified('password')){
        bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(err)
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err)
                user.password = hash
                next()
            })
        })
    } else{
        next()
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb){
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if (err) return cb(err)
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb){
    let user = this
    let token = jwt.sign(user._id.toHexString(), '1234')

    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })

}

userSchema.statics.findByToken = function(token, cb){
    let user = this

    jwt.verify(token, '1234', function(err, decoded){
        console.log('decoded: ',decoded)
        user.findOne({"token": token}, function(err, user){
            if(err) return cb(err)
            cb(null, user)
        })
    })
}

const User = mongoose.model('User', userSchema)
module.exports = { User }