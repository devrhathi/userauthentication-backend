//EXPRESS for handling requests
const express = require("express");
const app = express();
const cors = require("cors");
const PORT = process.env.PORT || 3001;

//for providing .env Secret Token Key to JWT Signing
require("dotenv").config();

//JWT for jwt auth
const jwt = require("jsonwebtoken");

//middleware to use json
app.use(express.json());
app.use(cors());

//some methods for Don't Repeat Your Code, (more optimizations can be done too)
const extractToken = (req) => {
  const loginHeader = req.headers["authorization"];
  const JWT_TOKEN = loginHeader && loginHeader.split(" ")[1];
  return JWT_TOKEN;
};

const createUser = (req) => {
  const user = {
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    address: req.body.address,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 5,
  };

  return user;
};

//Middleware to verify user
const verifyUserMiddleware = (req, res, next) => {
  const JWT_TOKEN = extractToken(req);
  if (JWT_TOKEN === null) {
    return res.sendStatus(401);
  }

  //verify token w given id pass
  jwt.verify(JWT_TOKEN, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json(err);
    }
    req.decoded = decoded;
    next();
  });
};

const editUserData = (req, old_data) => {
  const new_data = {
    username: req.body.username,
    email: req.body.email,
    password: old_data.password,
    address: req.body.address,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 5,
  };
  const NEW_JWT_TOKEN = jwt.sign(new_data, process.env.SECRET_KEY);

  return NEW_JWT_TOKEN;
};

//=======================REQUST HANDLING===========================

app.get("/", (req, res) => {
  res.status(201).send("Server Started");
});

app.post("/signup", (req, res) => {
  //Here exp is expiration time, 5 is the no. of minutes we want
  const user = createUser(req);
  let JWT_TOKEN = jwt.sign(user, process.env.SECRET_KEY);
  if (!JWT_TOKEN) {
    res.sendStatus(401);
  }
  res.status(201).json(JWT_TOKEN);
});

app.post("/login", verifyUserMiddleware, (req, res) => {
  if (
    req.body.email === req.decoded.email &&
    req.body.password === req.decoded.password
  ) {
    res.status(201).json({
      Authenticated: true,
    });
  } else {
    res.status(401).json({ AUTHENTICATION: "FAILED" });
  }
});

app.get("/userDetails", (req, res) => {
  //grab the token first
  const JWT_TOKEN = extractToken(req);

  jwt.verify(JWT_TOKEN, process.env.SECRET_KEY, (err, decoded) => {
    if (decoded) {
      res.status(201).json(decoded);
    } else {
      res.status(401).json({ err: "Token Expired" });
    }
  });
});

app.post("/editUserDetails", (req, res) => {
  //decode the token first
  const JWT_TOKEN = extractToken(req);
  let old_data;
  if (JWT_TOKEN === null) {
    res.sendStatus(401);
  }
  jwt.verify(JWT_TOKEN, process.env.SECRET_KEY, (err, decoded) => {
    old_data = decoded;
  });
  //now get the new fields, replace them, and create a new token (for another 5 minutes for user)
  const NEW_JWT_TOKEN = editUserData(req, old_data);
  if (NEW_JWT_TOKEN !== null) {
    res.status(201).json(NEW_JWT_TOKEN);
  } else {
    res.sendStatus(401);
  }
});

app.listen(3001);
