const express = require("express");
const {
  login,
  verifyOtp,
  forgotPassword,
  resetPassword,
  signup,
  verifyEmail,
} = require("../controllers/authController");

const {
  loginValidators,
  signupValidators,
  forgotPasswordValidators,
  resetPasswordValidators,
  otpValidator,
  verifyEmailTokenValidator,
} = require("./../middlewares/validators/authValidators");
const { validationChecker } = require("./../middlewares/validationChecker");

const router = express.Router();

router.post("/login", loginValidators, validationChecker, login);
router.post("/signup", signupValidators, validationChecker, signup);

router.post(
  "/forgot-password",
  forgotPasswordValidators,
  validationChecker,
  forgotPassword
);
router.post(
  "/reset-password/:resetToken",
  resetPasswordValidators,
  validationChecker,
  resetPassword
);
router.post("/verify-otp", otpValidator, validationChecker, verifyOtp);
router.post(
  "/verify-email/:token",
  verifyEmailTokenValidator,
  validationChecker,
  verifyEmail
);

module.exports = router;
