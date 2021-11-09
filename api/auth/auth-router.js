const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const buildToken = require("./buildToken");
const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const newUser = req.body;

  //bcrypt

  const rounds = process.env.BCRYPT_ROUNDS || 6;
  const hash = bcrypt.hashSync(newUser.password, rounds);
  newUser.password = hash;
  newUser.role_name = req.role_name;
  User.add(newUser)
    .then((resp) => {
      res.status(201).json({
        user_id: resp.user_id,
        username: resp.username,
        role_name: resp.role_name,
      });
    })
    .catch((err) => {
      next(err);
    });

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    const passwordValidated = bcrypt.compareSync(password, req.user.password);
    if (passwordValidated) {
      const token = buildToken(req.user);
      res.status(200).json({
        message: `${req.user.username} is back!`,
        token,
      });
    } else {
      next({ status: 401, message: "Invalid Credentials" });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
