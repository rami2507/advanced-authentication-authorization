const express = require("express");
const { restrictTo, protect } = require("../controllers/authController");
const { validationChecker } = require("./../middlewares/validationChecker");
const {
  getUserValidators,
  deleteUserValidators,
} = require("./../middlewares/validators/userValidators");
const {
  getAllUsers,
  getUser,
  deleteUser,
} = require("../controllers/userController");

const router = express.Router();

// IMPLEMENTING RBAC (ROLE-BASED ACCESS CONTROL)
router.use(protect, restrictTo("admin"));

router.route("/").get(getAllUsers);
router
  .route("/:id")
  .get(getUserValidators, validationChecker, getUser)
  .delete(deleteUserValidators, validationChecker, deleteUser);

module.exports = router;
