//jshint esversion:6
require("dotenv").config();
const bodyparser=require("body-parser");
const express=require("express");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLoacalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");


const app=express();

app.use(bodyparser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(express.static("public"));

//userDB ->DB name
mongoose.connect("mongodb://localhost:27017/userDB",
{useNewUrlParser:true});
mongoose.set("useCreateIndex",true);

//setting session
app.use(session({
    secret:"My Little Secret.",
    resave:false,
    saveUninitialized:false
}));

//initialize passport
app.use(passport.initialize());
app.use(passport.session());

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLoacalMongoose);
userSchema.plugin(findOrCreate);

//Model
const user=mongoose.model("user",userSchema);

passport.use(user.createStrategy());

//serialize and deserialzeiuser
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    user.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    //here find or create mean if Id is not found the create a id if found then dont (vice versa)
    user.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb( err, user);
    });
  }
));


app.get("/",function(req,res)
{
   res.render("home");
});

//authenticate using google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  
  //Callback for google
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res)
{
   res.render("login");
});

app.get("/register",function(req,res)
{
   res.render("register");
});


app.get("/secrets",function(req,res)
{
     user.find({
         "secret":{$ne:null}
     }, function(err,founduser)
     {
         if(err)
         {
             console.log(err);
         }
         else{
             if(founduser)
             {
                 res.render("secrets",{userWithSecrets:founduser});
             }
         }
     });
});


app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  });



app.post("/submit",function(req,res)
{
    const submittedSecret=req.body.secret;
    
    user.findById(req.user.id,function(err,foundUser){

        if(err)
        {
            console.log(err);
        }
        else{
            if(foundUser)
            {
                foundUser.secret=submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }

});
});

app.get("/logout",function(req,res)
{
     req.logOut();
     res.redirect("/");
});

//post method of register
app.post("/register",function(req,res)
{
    user.register({username:req.body.username}, req.body.password,function(err,user)
    {
        if(err)
        {
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function()
            {
                res.redirect("/secrets");
            })
        }
    })
});

//log in route 

app.post("/login",function(req,res)
{
  const newUser=new user(
      {
          username:req.body.username,
          password:req.body.password
      }
  ) ;
  req.login(newUser,function(err)
  {
      if(err)
      {
          //this method comes from passport
          console.log(err);
      }
      else{
        passport.authenticate("local")(req,res,function()
        {
            res.redirect("/secrets");
        })
      }
  })
});





//listen method
app.listen(3000,function()
{
  console.log("server started at port 3000");
});
