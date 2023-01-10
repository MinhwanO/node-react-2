const express = require('express')
const app = express()
const port = 5000
const mongoose = require('mongoose')
const { User } = require('./models/User')
const config = require('./config/key')
const cookieParser = require('cookie-parser')
const { auth } = require('./middleware/auth')
const cors = require('cors')

app.use(cors({
    origin: true,
    credentials: true,
}))

app.use(express.json()); //For JSON requests, application/json 분석해서 가져올수 있도록
app.use(express.urlencoded({extended: true}));//application/x-www-form-urlencoded 분석해서 가져올수 있도록

app.use(cookieParser())



// 몽고db 연결
mongoose
    .connect('mongodb+srv://minhwan:a12345@cluster0.mi9fstm.mongodb.net/?retryWrites=true&w=majority')
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.log(err))


app.get('/', (req, res) => {
    res.send('안녕하세요~~')
})

app.post('/api/users/register', (req, res) => {
    const user = new User(req.body)
    //save하기 전 User.js에서 비밀번호 암호화를 한다
    user.save((err, userInfo) => {
        if (err) return res.json({success: false, err})
        return res.status(200).json({success: true})
    })
})

app.post('/api/users/login', (req, res) => {
    User.findOne({email: req.body.email}, (err, user) => {
        if(!user){
            return res.json({
                loginSuccess: false,
                message: "제공된 이메일에 해당하는 유저가 없습니다"
            })
        }

        user.comparePassword(req.body.password, (err, isMatch)=>{
            if(!isMatch)
                return res.json({loginSuccess: false, message: "비밀번호가 틀렸습니다."})
        

        user.generateToken((err, user) => {
            if(err) return res.status(400).send(err);

            res.cookie("x_auth", user.token, {sameSite:'none', secure: true})
            .status(200)
            .json({
                loginSuccess: true,
                userId: user._id
            })
        })
    })
    })
})

app.post('/api/users/auth',auth, (req, res) => {
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true, // 0이면 일반유저, 그게 아니면 관리자
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
})

app.post('/api/users/logout',auth, (req, res) => {
    User.findOneAndUpdate({_id: req.user._id}, { token: "" }
    , (err, user) => {
        if(err) return res.json({success: false, err})
        return res.status(200).send({
            success: true
        })
    })
})


app.listen(port, () => {
    console.log(`listening on port ${port}!`)
})
