const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find();
  res.status(200).json({
    status: "success",
    results: users.length,
    data: { users },
  });
});

const getUser = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id);

  if (!user) {
    return res.status(404).json({
      status: "error",
      message: `NO user has found with that ID: ${id}`,
    });
  }

  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;
  await User.findByIdAndDelete(id);
  res.status(204).json({
    status: "success",
    data: null,
  });
});

module.exports = { getAllUsers, getUser, deleteUser };
