const User = require("./../models/userModel");
const sendEmail = require("../utils/emailService");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const AppError = require("./../utils/AppError");
const crypto = require("crypto");
const { promisify } = require("util");

const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

const validatePasswordStrength = (password) => {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUppercase &&
    hasLowercase &&
    hasNumber &&
    hasSpecialChar
  );
};

// Protect Middleware
const protect = asyncHandler(async (req, res, next) => {
  // 1) Getting Token And Check If It's There
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  if (!token)
    return next(
      new AppError("Your are not logged in! Please login to get access", 401)
    );
  // 2) Validate token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  // 3) Check If User Still Exist
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError("the user belonging to this token does no longer exist")
    );
  }
  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  next();
});

// User Singup
const signup = asyncHandler(async (req, res, next) => {
  const { name, email, password } = req.body;

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    return next(new AppError("Email already exists", 400));
  }

  if (!validatePasswordStrength(password)) {
    return next(
      new AppError(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character",
        400
      )
    );
  }

  const newUser = await User.create({
    name,
    email,
    password,
  });

  const verificationToken = newUser.createEmailVerificationToken();

  const message = `Use this link to verify your email: ${
    req.protocol
  }://${req.get("host")}/verify-email?token=${verificationToken}`;

  try {
    await sendEmail(newUser.email, "Email Verification", message);

    // Save the user with the new token and expiration
    await newUser.save();

    res.status(200).json({
      message: "Verification email sent!",
    });
  } catch (err) {
    // Clear token and expiration if email fails to send
    newUser.emailVerificationToken = undefined;
    newUser.emailVerificationExpires = undefined;
    await newUser.save(); // Save the changes

    next(err.message, 400);
  }
});

// Verify the email address after signing up
const verifyEmail = asyncHandler(async (req, res, next) => {
  const token = req.params.token;

  const hashedToken = hashToken(token);

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Invalid or expired token", 400));
  }

  user.emailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;

  await user.save();

  res.status(200).json({ message: "Email verified successfully" });
});

// User Login
const login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError("Invalid credentials", 401));
  }

  if (user.lockUntil && user.lockUntil > Date.now()) {
    return next(
      new AppError(
        "Your account has been locked due to too many failed login attempts. It will be unlocked in 1 hour.",
        400
      )
    );
  }

  if (!(await user.comparePassword(password))) {
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= 3) {
      user.failedLoginAttempts = 0;
      user.lockUntil = Date.now() + 60 * 60 * 1000; // Lock account for 1 hour
      await user.save();

      await sendEmail(
        user.email,
        "Account Locked",
        "Your account has been locked due to too many failed login attempts. It will be unlocked in 1 hour."
      );

      return next(
        new AppError(
          "Your account is locked due to multiple attempts, try again after 1 hour",
          400
        )
      );
    }

    await user.save();
    return next(
      new AppError(
        `Invalid credentials, you have ${
          3 - user.failedLoginAttempts
        } more attempts`,
        400
      )
    );
  }

  user.failedLoginAttempts = 0;
  user.lockUntil = undefined;
  await user.save();

  if (!user.emailVerified) {
    return next(
      new AppError("Your email is not verified yet. Please verify it first")
    );
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP

  user.otp = otp;
  user.otpExpiry = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

  await user.save();

  // Send OTP to user's email
  await sendEmail(user.email, "Your OTP", `Your OTP is ${otp}`);

  res.status(200).json({ message: "OTP sent to your email" });
});

// Verify OTP
const verifyOtp = asyncHandler(async (req, res, next) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email }).select("-password");

  if (!user || user.otp !== otp || Date.now() > user.otpExpiry) {
    return next(new AppError("Invalid or expired OTP", 401));
  }

  // OTP is Valid => Generate JWT
  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY }
  );

  // Clear OTP fields
  user.otp = undefined;
  user.otpExpiry = undefined;
  await user.save();

  res.status(200).json({ status: "success", data: { user, token } });
});

// RBAC (ROLE-BASED-ACCESS-CONTROL)
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You are not authorized to perform this action"),
        401
      );
    }
    next();
  };
};

// Forget Password
const forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError("There is no user with that email", 404));
  }

  const resetToken = user.createPasswordResetToken();

  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get(
    "host"
  )}/api/auth/resetPassword/${resetToken}`;

  try {
    await sendEmail(
      user.email,
      "Password Reset Link! (Valid for 10 minutes)",
      `Use this link to reset your password: ${resetUrl}`
    );
    res.status(200).json({ message: "Token sent to email" });
  } catch (err) {
    user.passwordResetExpires = undefined;
    user.passwordResetToken = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(400).json({
      status: "error",
      err,
    });
  }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res, next) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  if (!validatePasswordStrength(password)) {
    return next(
      new AppError(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character",
        400
      )
    );
  }

  user.password = password;
  user.passwordResetExpires = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  const token = await jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRY,
    }
  );
  res.status(200).json({ token, message: "Password successfully updated" });
});

module.exports = {
  login,
  verifyOtp,
  restrictTo,
  protect,
  forgotPassword,
  resetPassword,
  signup,
  verifyEmail,
};
