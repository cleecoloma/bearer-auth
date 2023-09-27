'use strict';

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET = process.env.TEST_SECRET || 'TEST_SECRET';
const usedTokens = [];

const userSchema = (sequelize, DataTypes) => {
  const model = sequelize.define('User', {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },

    // One time use token
    token: {
      type: DataTypes.VIRTUAL,
      get() {
        if (usedTokens.includes(this.username)) {
          return null;
        }
        const token = jwt.sign({ username: this.username }, SECRET);
        usedTokens.push(this.username);
        return token;
      },
    },
    // 15 min timed tokens
    // token: {
    //   type: DataTypes.VIRTUAL,
    //   get() {
    //     const expirationTime = Math.floor(Date.now() / 1000) + 900;
    //     return jwt.sign(
    //       { username: this.username, exp: expirationTime },
    //       SECRET
    //     );
    //   },
    // },
  });

  model.beforeCreate(async (user) => {
    let hashedPass = await bcrypt.hash(user.password, 10);
    user.password = hashedPass;
  });

  // Basic AUTH: Validating strings (username, password)
  model.authenticateBasic = async function (username, password) {
    const user = await this.findOne({ where: { username }});
    const valid = await bcrypt.compare(password, user.password);
    if (valid) {
      console.log("here are user model authenticate: ", user)
      return user;
    }
    throw new Error('Invalid User');
  };

  // Bearer AUTH: Validating a token
  model.authenticateToken = async function (token) {
    try {
      const parsedToken = jwt.verify(token, SECRET);
      const user = this.findOne({ where: { username: parsedToken.username }});
      if (user) {
        return user;
      } else {
        throw new Error('User Not Found');
      }
    } catch (e) {
      throw new Error(e.message);
    }
  };

  return model;
};

module.exports = userSchema;
