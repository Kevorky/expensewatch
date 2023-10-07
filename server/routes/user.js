var mongoose = require("mongoose");
var User = require("../models/user");
var jwt = require("jsonwebtoken");
var config = require("../config");

exports.signup = async function (req, res, next) {
  // Check for registration errors
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;

  if (!firstname || !lastname || !email || !username || !password) {
    return res.status(422).json({
      success: false,
      message: "Posted data is not correct or incomplete.",
    });
  }

  try {
    const existingUser = await User.findOne({ username: username });

    // If user is not unique, return error
    if (existingUser) {
      return res.status(201).json({
        success: false,
        message: "Username already exists.",
      });
    }

    // If no error, create account
    let oUser = new User({
      firstname: firstname,
      lastname: lastname,
      email: email,
      username: username,
      password: password,
    });

    await oUser.save();

    res.status(201).json({
      success: true,
      message:
        "User created successfully, please login to access your account.",
    });
  } catch (err) {
    console.log(err);

    res
      .status(400)
      .json({ success: false, message: "Error processing request " + err });
  }
};

exports.login = async function (req, res, next) {
  try {
    // find the user
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      res
        .status(201)
        .json({ success: false, message: "Incorrect login credentials." });
    } else if (user) {
      user.comparePassword(req.body.password, function (err, isMatch) {
        if (isMatch && !err) {
          let token = jwt.sign(
            JSON.parse(JSON.stringify(user)),
            config.secret,
            {
              expiresIn: config.tokenexp,
            }
          );

          let last_login = user.lastlogin;

          // login success update last login
          user.lastlogin = new Date();

          user.save().then((saveDoc) => {
            res.status(201).json({
              success: true,
              message: {
                userid: user._id,
                username: user.username,
                firstname: user.firstname,
                lastlogin: last_login,
              },
              token: token,
            });
          });
        } else {
          res
            .status(201)
            .json({ success: false, message: "Incorrect login credentials." });
        }
      });
    }
  } catch (err) {
    console.log(err);

    res
      .status(400)
      .json({ success: false, message: "Error processing request " + err });
  }
};

exports.authenticate = function (req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers["authorization"];
  //console.log(token);
  if (token) {
    console.log(token);
    jwt.verify(token, config.secret, function (err, decoded) {
      if (err) {
        console.log(err.message);
        return res.status(201).json({
          success: false,
          message: "Authenticate token expired, please login again.",
          errcode: "exp-token",
        });
      } else {
        req.decoded = decoded;
        next();
      }
    });
  } else {
    return res.status(201).json({
      success: false,
      message: "Fatal error, Authenticate token not available.",
      errcode: "no-token",
    });
  }
};

exports.getuserDetails = function (req, res, next) {
  User.find({ _id: req.params.id })
    .then((user) => {
      res.status(201).json({
        success: true,
        data: user,
      });
    })
    .catch((err) => {
      res
        .status(400)
        .json({ success: false, message: "Error processing request " + err });
    });
};

exports.updateUser = function (req, res, next) {
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;
  const email = req.body.email;
  const userid = req.params.id;

  if (!firstname || !lastname || !email || !userid) {
    return res.status(422).json({
      success: false,
      message: "Posted data is not correct or incompleted.",
    });
  } else {
    User.findById(userid)
      .then((user) => {
        if (user) {
          user.firstname = firstname;
          user.lastname = lastname;
          user.email = email;
        }

        user
          .save()
          .then((saveDoc) => {
            res.status(201).json({
              success: true,
              message: "User details updated successfully",
            });
          })
          .catch((err) => {
            res.status(400).json({
              success: false,
              message: "Error processing request " + err,
            });
          });
      })
      .catch((err) => {
        res
          .status(400)
          .json({ success: false, message: "Error processing request " + err });
      });
  }
};

exports.updatePassword = function (req, res, next) {
  const userid = req.params.id;
  const oldpassword = req.body.oldpassword;
  const password = req.body.password;

  if (!oldpassword || !password || !userid) {
    return res.status(422).json({
      success: false,
      message: "Posted data is not correct or incompleted.",
    });
  } else {
    User.findOne({ _id: userid })
      .then((user) => {
        if (user) {
          user.comparePassword(oldpassword, function (err, isMatch) {
            if (isMatch && !err) {
              user.password = password;

              user
                .save()
                .then((saveDoc) => {
                  res.status(201).json({
                    success: true,
                    message: "Password updated successfully",
                  });
                })
                .catch((err) => {
                  res.status(400).json({
                    success: false,
                    message: "Error processing request " + err,
                  });
                });
            } else {
              res
                .status(201)
                .json({ success: false, message: "Incorrect old password." });
            }
          });
        }
      })
      .catch((err) => {
        res
          .status(400)
          .json({ success: false, message: "Error processing request " + err });
      });
  }
};
