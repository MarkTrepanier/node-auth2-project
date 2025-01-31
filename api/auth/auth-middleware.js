const { default: jwtDecode } = require("jwt-decode");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const User = require("../users/users-model.js");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    next({ status: 401, message: "token required" });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next({
        status: 401,
        message: "token invalid",
      });
    }
    req.decodedJwt = decoded;
    next();
  });
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedJwt.role_name !== role_name) {
    next({
      status: 403,
      message: "This is not for you",
    });
  } else {
    next();
  }
};

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  const [user] = await User.findBy({ username });
  if (!user) {
    next({ status: 401, message: "invalid credentials" });
  } else {
    req.user = user;
    next();
  }
};

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  const roleName = !role_name ? "student" : role_name.trim();

  if (roleName === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  }
  if (roleName.length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  }
  req.role_name = roleName;
  next();
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
