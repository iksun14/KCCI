const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');

function readUsers() {
  const users = JSON.parse(fs.readFileSync('./db/users.json').toString());
  return users;
}

function findOne(identity) {
  const users = readUsers();
  const selectedUser = users.filter(function(user){
    return identity === user.identity;
  })[0];
  return selectedUser;
}

function findOneByNick(nickname) {
  const users = readUsers();
  const selectedUser = users.filter(function(user){
    return nickname === user.nickname;
  })[0];
  return selectedUser;
}

function createUser(identity, password, nickname, email, createdAt){
  const user = {
    identity,
    password,
    nickname,
    email,
    createdAt,
  };
  const users = readUsers();
  users.push(user);
  fs.writeFileSync('./db/users.json', JSON.stringify(users, null, 2))
}

function encryptStr(str, salt) {
  return crypto.pbkdf2Sync(str, salt, 5326, 256, 'sha256').toString('hex');
}

router.post('/login', function(req, res) {
  const identity = req.body.identity;
  const selectedUser = findOne(identity);

  if (selectedUser) {
    const password = encryptStr(req.body.password, selectedUser.createdAt.toString());
    if (selectedUser.password === password) {
      req.session.userInfo = {
        ...selectedUser
      };
      return res.send("Success");
    }
  }
  res.status(401).send("Bad Authorization");
});

router.post('/logout', function(req, res) {
  req.session.userInfo = undefined;
  res.send("Success");
});

router.post('/create', function(req, res) {
  const identity = req.body.identity;
  const password = req.body.password;
  const nickname = req.body.nickname;
  const email = req.body.email || '';
  if (!identity || !password || !nickname) {
    return res.status(400).send("Some parameter lost");
  }
  const existUser = findOne(identity);
  const existUserByNick = findOneByNick(nickname);
  if (existUser || existUserByNick) {
    return res.status(400).send("Identity or nickname is already exist.");
  }
  const createdAt = new Date().getTime();
  createUser(identity, encryptStr(password, createdAt.toString()), nickname, email, createdAt);
  res.send("Success");
});

router.get("/point", function(req, res) {
  if (!req.session.userInfo) {
    return res.status(401).send("Unauthorized");
  }
  res.send(req.session.userInfo.point.toString());
});

module.exports = router;