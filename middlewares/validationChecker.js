const { validationResult } = require("express-validator");

const validationChecker = (req, res, next) => {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    return res.status(400).json({
      status: "validation error",
      errors: result.errors,
    });
  }

  next();
};

module.exports = { validationChecker };
