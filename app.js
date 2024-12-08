const express = require("express");
const dotenv = require("dotenv");
const userRoutes = require("./routes/userRoutes");
const authRoutes = require("./routes/authRoutes");
const cookieParser = require("cookie-parser");
const globalErrorHandling = require("./controllers/errorController");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const helmet = require("helmet");
const hpp = require("hpp");

dotenv.config({ path: ".env" });

// Defining rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    message: "Too many requests, please try again later.",
  },
});

// App Initialization
const app = express();

// Apply rate limiter to all requests
app.use(globalLimiter);

// Apply express-mongo-sanitize to sanitize incoming requests
app.use(mongoSanitize());

// Apply xss-clean to sanitize incoming requests
app.use(xss());

// Apply Helmet to secure HTTP headers
app.use(helmet());

// Apply hpp to prevent HTTP Parameter Pollution attacks
app.use(hpp());

// Parsing Data
app.use(express.json());
app.use(cookieParser());

// Mounting app routes
app.use("/auth", authRoutes);
app.use("/users", userRoutes);

// Global Error Handling Middleware
app.use(globalErrorHandling);

module.exports = app;
