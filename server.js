const app = require("./app");
const mongoose = require("mongoose");

const DB = process.env.MONGO_STRING;
// DB Connection
mongoose
  .connect(DB)
  .then(() => {
    console.log("DB has been connected successfuly!");
  })
  .catch((err) => {
    console.error(err);
  });

// Running The Server
const port = process.env.APP_PORT || 3000;
app.listen(port, () => {
  console.log(`server is running on port ${port}....`);
});
