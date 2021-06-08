require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
// Session Middleware for creating session cookies
const session = require("express-session");
// Authentification and security package
const passport = require("passport");
// Middleware to handle interactions with database using local strategy
const passportLocalMongoose = require("passport-local-mongoose");
// Passport specific google's strategy authentification
const GoogleStrategy = require("passport-google-oauth20").Strategy;
// Find or creates user after retrieval of user info from third-party
const findOrCreate = require("mongoose-findorcreate");
const PORT = process.env.PORT || 3000;

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Initializing express-session middleware
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(
  `mongodb+srv://admin-kizito:${process.env.DATABASE_PASSWORD}@cluster0.buwiw.mongodb.net/secretDB`,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// Google strategy initialization to be passed as Middleware to passport
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://stormy-hollows-36236.herokuapp.com/auth/google/secrets",
      // Given the sunsetting of Google+, this property fetches user info from google
      useProfileUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (_accessToken, _refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// Google authentification route for users to register
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

// Google redirect route to handle local authentification of user
app.get(
  "https://stormy-hollows-36236.herokuapp.com/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (_req, res) => {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  }
);

app.get("/", (_req, res) => {
  res.render("home");
});

app.get("/register", (_req, res) => {
  res.render("register");
});

app.get("/login", (_req, res) => {
  res.render("login");
});

// Handles rendering of all secrets stored in the database
app.get("/secrets", (_req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersSubmittedSecrets: foundUsers });
      }
    }
  });
});

app.get("/logout", (req, res) => {
  // Passport specific logout function
  req.logout;
  res.redirect("/");
});

app.get("/submit", (req, res) => {
  res.render("submit");
});

// Handles submission of user secret
app.post("/submit", (req, res) => {
  // Save user secret after input
  const submittedSecret = req.body.secret;

  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      } else {
        return console.log("Not found");
      }
    }
  });
});

// Register user using the local strategy
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

// Login user using local strategy
app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  // Passport specific login handler
  req.login(user, (err) => {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(PORT, () => {
  console.log("Server running on port 3000");
});
