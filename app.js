var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");
const MongoStore = require("connect-mongo");
const User = require("./models/user");
const mongoose = require("mongoose");
require("dotenv").config();

mongoose.set("strictQuery", false);
const mongoDB = process.env.DB_STRING;

main().catch((err) => console.log(err));
async function main() {
  await mongoose.connect(mongoDB, { dbName: "members" });
}
// const connection = mongoose.createConnection(process.env.DB_STRING);
const sessionStore = MongoStore.create({
  mongoUrl: process.env.SESSION_STORE,
  dbName: "sessions"
});
var app = express();
app.set("view engine", "ejs");
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);
app.use(passport.session());
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  res.locals.isMember = req.user?.is_member;
  next();
});

const MESSAGES = [];
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("index", { msgList: MESSAGES });
  }
  else {
    res.render("index", { msgList: MESSAGES });
  }
});

app.get("/sign-up", (req, res) => res.render("sign-up", { errors: null }));

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post(
  "/sign-up",
  body("password")
    .isLength({ min: 5 })
    .withMessage("Password must be at least 5 characters"),
  body("confirmpwd")
    .custom((value, { req }) => {
      return value === req.body.password;
    })
    .withMessage("Password does not match with confirmation"),
  async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      res.render("sign-up", {
        errors: errors.array(),
      });
      return;
    }

    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err);
      }
      try {
        const user = new User({
          username: req.body.username,
          password: hashedPassword,
          first_name: req.body.fname,
          family_name: req.body.lname,
          is_member: false
        });
        const result = await user.save();
        res.redirect("/");
      } catch (err) {
        return next(err);
      }
    });
  }
);

app.get("/join-club", (req, res) => res.render("join-club", { errors: null }))

app.post("/join-club", (req, res) => {
  if (req.isUnauthenticated()) {
    res.render("join-club", { errors: [{ msg: "Sign in first!" }] })
  } else {
    if (req.body.code == "secret_code") {
      user = req.user;
      user.is_member = true;
      user.save()
      res.redirect("/");
    }
    else {
      res.render("join-club", { errors: [{ msg: "Wrong code!" }] })
    }
  }

})

app.get("/message", (req, res) => res.render("message", { errors: null }))

app.post("/message", (req, res) => {
  if (req.isUnauthenticated()) {
    res.render("/message", { errors: [{ msg: "Sign in first!" }] })
  } else {
    user = req.user;
    msg = { user: user.first_name, message: req.body.msg, date: (new Date()).toDateString() }
    MESSAGES.push(msg)
    res.redirect("/")
  }

})

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

module.exports = app;
