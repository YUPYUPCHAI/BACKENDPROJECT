require("dotenv").config()
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')
const express = require("express")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")
const app = express()

// database setup here
const createTables = db.transaction(()=>{
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
    ).run()
})

createTables()
//database setup end here

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function(req,res,next) {
    res.locals.errors=[]
    // try to decode incoming cookoe
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp,process.env.JWTSECRET)
        req.user = decoded
    } catch(err){
        req.user = false
    }
    
    res.locals.user=req.user
    console.log(req.user)

    next()
})

app.get("/",(req,res)=>{    
    if (req.user){
        return res.render("dashboard")
    }
    res.render("homepage")
})  

app.get("/login",(req,res)=>{
    res.render("login")
})
app.get("/logout",(req,res)=>{
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})
app.post("/login",(req,res)=>{
    let errors = []

    if (typeof req.body.username !="string") req.body.username=""
    if (typeof req.body.password !="string") req.body.password=""

    if (req.body.username.trim()=="")errors=["Invalid username/password"]
    if (req.body.password=="")errors=["Invalid username/password"]
    
    if (errors.length){
        return res.render("login",{errors})
    }
    const userInQS = db.prepare("SELECT * FROM users WHERE USERNAME =?")
    const userInQ = userInQS.get(req.body.username)

    if(!userInQ){
        errors=["Invalid username/password"]
        return res.render("login",{errors})
    }
    const matchornot = bcrypt.compareSync(req.body.password,userInQ.password)
    if (!matchornot){
        errors=["Invalid username/password"]
        return res.render("login",{errors})
    }
    // give them a cookies
    const ourToken = jwt.sign(
        {exp: Math.floor(Date.now()/1000)+ 60 * 60 * 24,skyColor :"blue",userid: userInQ.id,username: userInQ.username},
        process.env.JWTSECRET
    )

    res.cookie("ourSimpleApp",ourToken,{
        httpOnly:true,
        secure:true,
        sameSite: "strict",
        maxAge: 1000 * 60 *60 *24
    })
    res.redirect("/")
    
    //and get themn back to homepage
})
app.post("/register",(req,res)=>{
    const errors = []

    if (typeof req.body.username !="string") req.body.username=""
    if (typeof req.body.password !="string") req.body.password=""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("You must provide a username.")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters.")
    if (req.body.username && req.body.username.length > 10) errors.push("Username must not more then 10 characters.")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letter and number")
    
    //check if username is taking
    const usernameSm = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameC = usernameSm.get(req.body.username)

    if (usernameC) errors.push("USER NAME IS TAKE")

    if (!req.body.password) errors.push("You must provide a password.")
    if (req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters.")
    if (req.body.password && req.body.password.length > 20) errors.push("Password must not more then 20 characters.")    
    


    if (errors.length){
        return res.render("homepage",{errors})
    }
    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password,salt)

    const ourStatement = db.prepare("INSERT INTO users (username,password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username,req.body.password)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)
    //give a cookie to user
    const ourToken = jwt.sign({exp: Math.floor(Date.now()/1000)+ 60 * 60 * 24,skyColor :"blue",userid: ourUser.id,username: ourUser.username},process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourToken,{
        httpOnly:true,
        secure:true,
        sameSite: "strict",
        maxAge: 1000 * 60 *60 *24
    })
    res.redirect("/")
    
})

app.listen(3000)
console.log("PORT U ARE USEING IS 3000")