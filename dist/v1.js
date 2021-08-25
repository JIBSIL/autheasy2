const { MongoClient } = require("mongodb");
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");

// Connection URL
const databaseConnectionString =
  "use_your_mongo_here";

const client = new MongoClient(databaseConnectionString);

// Database Name
const dbName = "auth";

const jwtsecret =
  "yoursecret";

const app = express();
const port = 3000;
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

async function main() {
  await client.connect();
  const db = client.db(dbName);
  const collection = db.collection("dev");
  // Character limit
  const RegExpFilter = /^.{3,64}$/;
  const RegExpFilterPassword = /^.{7,64}$/;

  app.get("/", (req, res) => {
    res.send("You've reached the Example Authentication API!");
  });

  app.post("/signup", async (req, res) => {
    try {
      if (
        RegExpFilter.test(req.body.username) &&
        RegExpFilterPassword.test(req.body.password) === true
      ) {
        if (await collection.findOne({ username: req.body.username })) {
          res.send("USER_EXISTS");
        } else {
          const salt = bcrypt.genSaltSync(10);
          const hash = bcrypt.hashSync(req.body.password, salt);
          await collection.insertOne({
            username: req.body.username,
            password: hash,
            isAdmin: false // By default, this can be changed by the real admin in MongoDB
          });
          res.send("OK");
        }
      } else {
        res.send({ error: "ERR_BAD_CHARACTERS" });
      }
    } catch (error) {
      res.status(500).send({ error: "ERR_UNKNOWN_ERROR" });
    }
  });

  app.post("/login", async (req, res) => {
    try {
      if (
        RegExpFilter.test(req.body.username) &&
        RegExpFilterPassword.test(req.body.password) === true
      ) {
        const findUser = await collection.findOne({
          username: req.body.username
        });
        if (findUser) {
          const comparePassword = await bcrypt.compare(
            req.body.password,
            findUser.password
          );
          if (comparePassword) {
            let isAdmin = findUser.isAdmin;
            const token = jwt.sign(
              { username: findUser.username, isAdmin: isAdmin },
              jwtsecret,
              {
                expiresIn: 86400
              }
            );
            res
              .cookie("token", token, { httpOnly: true })
              .status(200)
              .send({ AUTH: "AUTH", username: req.body.username, isAdmin });
          } else {
            res.send("NOAUTH");
          }
        } else {
          res.send("NOUSER");
        }
      } else {
        res.send({ error: "ERR_BAD_CHARACTERS" });
      }
    } catch (error) {
      res.status(500).send({ error: "NOAUTH_UNKNOWN_ERR" });
    }
  });

  app.get("/authenticatedroute", (req, res) => {
    try {
      jwt.verify(req.cookies.token, jwtsecret, (error, decoded) => {
        res.send({
          isValid: error || decoded === undefined ? false : true,
          user: { username: decoded.username, isAdmin: decoded.isAdmin }
        });
      });
    } catch (error) {
      if (error.message === "Cannot read property 'username' of undefined") {
        res.send({ error: "NOAUTH_ERR_POSSIBLE_SPOOF" });
      } else {
        res.status(500).send({ error: "NOAUTH_UNKNOWN_ERROR" });
      }
    }
  });

  app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
  });
}

main().catch(console.error);
