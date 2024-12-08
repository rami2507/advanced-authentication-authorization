const { body, param } = require("express-validator");

const loginValidators = [
  body("email")
    .notEmpty()
    .withMessage("Please enter your email")
    .isEmail()
    .withMessage("Please enter valid email address"),

  body("password").notEmpty().withMessage("Please enter your password"),
];

const signupValidators = [
  body("name").notEmpty().withMessage("Please enter your name"),
  body("email").notEmpty().withMessage("Please enter your email"),
  body("password").notEmpty().withMessage("Please enter your password"),
];

const forgotPasswordValidators = [
  body("email")
    .notEmpty()
    .withMessage("Please enter your email")
    .isEmail()
    .withMessage("Please enter a valid email address"),
];

const resetPasswordValidators = [
  param("resetToken").notEmpty().withMessage("Please provide a reset token"),
  body("password").notEmpty().withMessage("Please enter a password password"),
];

const otpValidator = [
  body("otp")
    .notEmpty()
    .withMessage("Please enter the OTP sent to your email")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be exactly 6 digits")
    .isNumeric()
    .withMessage("OTP must be a number"),

  body("email")
    .notEmpty()
    .withMessage("please provide the email address")
    .isEmail()
    .withMessage("please provide a valid email address"),
];

const verifyEmailTokenValidator = [
  param("token").notEmpty().withMessage("Please provide a verification token"),
];

module.exports = {
  loginValidators,
  signupValidators,
  forgotPasswordValidators,
  resetPasswordValidators,
  otpValidator,
  verifyEmailTokenValidator,
};
