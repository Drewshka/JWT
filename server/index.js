const express = require("express");
const app = express();
const db = require("./models");
const { Users } = require("./models");

const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createToken, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());

app.post("/register", (req, res) => {
  //   res.json("USER REGISTERED");
  const { username, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    Users.create({
      username: username,
      password: hash,
    })
      .then(() => {
        res.json("USER REGISTERED");
      })
      .catch((err) => {
        if (err) {
          res.status(400).json({ error: err });
        }
      });
  });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await Users.findOne({ where: { username: username } });

  if (!user) res.status(400).json({ error: "User Doesn't Exist" });

  const dbPassword = user.password;
  bcrypt.compare(password, dbPassword).then((match) => {
    if (!match) {
      res
        .status(400)
        .json({ error: "Wrong Username and Password Combination!" });
    } else {
      //give us access to token we are creating
      const accessToken = createToken(user);
      //create cookie and store in user's browser
      res.cookie("access-token", accessToken, {
        //expire after 30 days
        maxAge: 60 * 60 * 24 * 30 * 1000,
        //don't want user to have access to their cookie in their browser
        httpOnly: true,
      });

      res.json("Logged In");
    }
  });
});

app.get("/profile", validateToken, (req, res) => {
  //* if there are no cookies, user will not be authenticated
  res.json("profile");
});

db.sequelize.sync().then(() => {
  app.listen(3001, () => {
    console.log("SERVER RUNNING ON PORT 3001");
  });
});
