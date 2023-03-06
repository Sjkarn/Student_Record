const jwt = require("jsonwebtoken");
const { isValidObjectId } = require("mongoose");
const studentModel = require("../models/studentModel");

const authentication = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];

    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
      return res
        .status(400)
        .send({ status: false, message: "Token not present" });
    }

    const decoded = jwt.verify(token, "secreateKey");

    req.token = decoded;

    next();
  } catch (error) {
    return res.status(500).send({ status: false, message: error.message });
  }
};

const authorization = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const verifyUser = req.token.userId;

    let userData = await studentModel.findOne({ userId: userId });
    if (!isValidObjectId(userId)) {
      return res
        .status(400)
        .send({ status: false, message: "please provide valid userId" });
    }
    if (!userData) {
      return res.status(404).send({ status: false, message: "user Not found" });
    }

    if (userData.userId != verifyUser) {
      return res.status(403).send({
        status: false,
        message: "Unauthorized Access try with new Student details",
      });
    }
    next();
  } catch (err) {
    res.status(500).send({ status: false, message: err.message });
  }
};

module.exports = { authentication, authorization };