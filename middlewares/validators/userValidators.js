const { param } = require("express-validator");

const getUserValidators = [
  param("id")
    .notEmpty()
    .withMessage("id is required")
    .isMongoId()
    .withMessage("the id provided is not a valid mongoDB id"),
];

const deleteUserValidators = [
  param("id")
    .notEmpty()
    .withMessage("id is required")
    .isMongoId()
    .withMessage("the id provided is not a valid mongoDB id"),
];

module.exports = { getUserValidators, deleteUserValidators };
