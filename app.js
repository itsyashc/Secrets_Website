//  Requirements //

require("dotenv").config()
const express = require("express");
const ejs = require("ejs");
const bobyParser = require("body-parser");
const mongoose = require("mongoose");

// const encrypt = require("mongoose-encryption");    {{level 2}}

// const md5 = require("md5");   {{Level 3}}

// const bcrypt = require("bcrypt"); {{Level 4}}
// const saltRounds = 10;

// {{Level 5 & 6}}
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

//  {{Level 6}}
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bobyParser.urlencoded({extended:true}));

// {{Level 5 & 6}}
app.use(session({
    secret:"If this secret exposed then world will end.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

//  Database //
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose); // {{Level 5 & 6}}
userSchema.plugin(findOrCreate);   // {{Level 6}}

// Encryption.   {{level 2}}
// const secretKey = process.env.SECRET;
// userSchema.plugin(encrypt, {secret: secretKey, encryptedFields: ["password"]});

const User = mongoose.model("User", userSchema);

// {{Level 5 & 6}}
passport.use(User.createStrategy());
// {{Level 5}}
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// {{Level 6}}
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

// {{Level 6}}
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback: true
},
function(request, accessToken, refreshToken, profile, done){
    console.log(profile);
    User.findOrCreate({googleId: profile.id}, function(err, user){
        return done(err, user);
    });
}));

//  Requests & Response   //

// GET REQ.

app.get("/", (req, res)=>{
    res.render("home");
});

app.get("/login", (req, res)=>{
    res.render("login");
});

app.get("/register", (req, res)=>{
    res.render("register");
});

app.get("/secrets", (req, res)=>{
    if (req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, function(err, foundUsers){
            if (err){
                console.log(err);
            } else {
                if(foundUsers){
                    res.render("secrets", {usersWithSecrets: foundUsers});
                }
            }
        })
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", (req, res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res)=>{
    req.logout(function(err){
        if (err){
            console.log(err);
        }
    });  //  {{Level 5 & 6}}
    res.redirect("/");
});

// {{Level 6}}
app.get("/auth/google",
passport.authenticate("google", {scope: ["email", "profile"]})
);
app.get("/auth/google/secrets",
passport.authenticate("google",{
    successRedirect: "/secrets",
    failureRedirect: "/login",
}));

// POST REQ.

app.post("/register", (req, res)=>{

    // {{Level 5}}
    const newUsername = req.body.username;
    const newPassword = req.body.password;

    User.register({username: newUsername}, newPassword, function(err, user){
        if (err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    })

    //    {{Level 4}}
    // const userPlainTextPassword = req.body.password;
    // bcrypt.hash(userPlainTextPassword, saltRounds, function(err, hash){
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    
    //     newUser.save((err)=>{
    //         if (!err){
    //             res.render("secrets");
    //         } else {
    //             console.log(err);
    //         }
    //     })
    // })

    //    {{Level 3}}
    // const newUser = new User({
    //     email: req.body.username,
    //     password: md5(req.body.password)
    // });

    // newUser.save((err)=>{
    //     if (!err){
    //         res.render("secrets");
    //     } else {
    //         console.log(err);
    //     }
    // });
});

app.post("/login", (req, res)=>{

    // {{Level 5}}

    // entered login credentials
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    // to verify 
    req.login(user, function(err){
        if (err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

    // const enteredUsername = req.body.username;
    // // const enteredPassword = md5(req.body.password);   {{Level 3}}
    // const enteredPassword = req.body.password;

    // User.findOne({email: enteredUsername}, function(err, foundUser){

    //     if (err){
    //         console.log(err);
    //     } else {

    //         //   {{Level 4}}
    //         // if (foundUser){
    //         //     bcrypt.compare(enteredPassword, foundUser.password, function(err, result){
    //         //         if (result === true){
    //         //             res.render("secrets");
    //         //         } else {
    //         //             res.render("failed", {failedMSG: "You entered a wrong password."});
    //         //         }
    //         //     })

    //         } else{
    //             res.render("failed", {failedMSG: "Your entered username is not registered, please register first."});
    //         }
    //     }
    // })
})

app.post("/submit", (req, res)=>{
    const submittedSecret = req.body.secret;
    // console.log(req.user.id);
    User.findById({_id: req.user.id}, function(err, foundUser){
        if (err){
            console.log(err);
        } else {
            if (foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })
});

//  Port  //

app.listen(3000, ()=> {
    console.log("Server is successfully started at port 3000.")
})