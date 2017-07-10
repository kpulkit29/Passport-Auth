var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var expressValidator=require("express-validator");
mongoose.Promise = require("bluebird");
mongoose.connect('mongodb://localhost:27017/auth',{useMongoClient:true});
var passport=require("passport");
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var notifier = require('node-notifier');
router.use(expressValidator());
//Schemas
log_check=false;
var Schema = mongoose.Schema;
var userDataSchema = new Schema({
  name:String,
  password:String,
  email:String,
  username:String
}, {collection: 'auth1'});

//funtion to authenticate
function ensureAuth(req,res,next){
     if(req.isAuthenticated()){
return next();
     }
     else{
       notifier.notify("You are not logged in");
       res.redirect("/login");
     }
}
var UserData = mongoose.model('UserData', userDataSchema);
/* GET home page. */
router.get('/',ensureAuth,function(req, res, next) {
  res.render("index");
});
router.get('/login', function(req, res, next) {
  res.render('login');
});
//register
router.get('/register', function(req, res, next) {
  res.render('register');
});
router.post('/register', function(req, res, next) {
  var name=req.body.name;
  var password=req.body.password;
  var password2=req.body.password2;
  var email=req.body.email;
  var user=req.body.username;
  req.checkBody("name","required").notEmpty();
  req.checkBody("username","required").notEmpty();
  req.checkBody("password","required").notEmpty();
  req.checkBody("password2","passwords do not match").equals(password);
  req.checkBody("email","Not a valid email").isEmail();
  var errs=req.validationErrors();
  if(errs){
    res.render("register",{error:errs});
  }
  else{
    var item={
      "name":name,
      "username":user,
      "password":password,
       "email":email
    }
    var insert=new UserData(item);
    insert.save();
    console.log("saved");
    res.redirect("/login");
  }
});
passport.serializeUser(function(user, done) {
    done(null, user.id); 

});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    UserData.findById(id, function(err, user) {
        done(err, user);
    });
});
//facebook Strategy
passport.use(new FacebookStrategy({
	    clientID:'1455810978051841',
	    clientSecret:'bb450fc83a4cc39c5c154acb99794007',
	    callbackURL:'http://localhost:3000/auth/facebook/callback',
      profileFields: ['id', 'displayName', 'photos', 'email']
	  },
	  function(accessToken, refreshToken, profile, done) {
	    	process.nextTick(function(){
          console.log(profile);
	    		UserData.findOne({'email':profile.emails[0].value}, function(err, user){
	    			if(err)
	    				return done(err);
	    			if(user)
	    				return done(null, user);
	    			else {
	    				var newUser = new UserData();
	    				newUser.name = profile.name.givenName + ' ' + profile.name.familyName;
              newUser.username = profile.displayName;
	    				newUser.email = profile.emails[0].value;

	    				newUser.save(function(err){
	    					if(err)
	    						throw err;
	    					return done(null, newUser);
	    				})
	    				
	    			}
	    		});
	    	});
	    }

	));
//to use LocalStrategy
passport.use(new LocalStrategy(
   function(username,password,done){
     UserData.findOne({"username":username},function(err,user){
          if(err){console.log(err);}
          if(!user){
        return done(null, false, { message: 'Incorrect username.' });
          }
          if(user){
            UserData.findOne({"password":password},function(err,isMatch){
               if(isMatch===null){
                  return done(null, false, { message: 'Incorrect password.' });
               }
               else{
                 return done(null,user);
               }
            });
          }
     });
   }
));
router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/login'}),
  function(req,res,next) {
    notifier.notify("you have been logged in");
    res.redirect('/');
  });

router.get("/show",function(req,res,next){
  UserData.find({},function(err,doc){
    if(err){console.log(err)}
    console.log(doc);
    res.send("1");
  });
});
router.get("/logout",function(req,res,next){
   req.logout();
   notifier.notify("You have succesfully logged out");
   res.redirect("/login");
});
router.get('/auth/facebook', passport.authenticate('facebook',{scope:['email']}));

	router.get('/auth/facebook/callback', 
	  passport.authenticate('facebook', { successRedirect: '/',
	                                      failureRedirect: '/login' }),function(req,res,next){
                    res.redirect("/");                      
                                        });

module.exports = router;
