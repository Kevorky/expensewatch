const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require("morgan");
const mongoose = require("mongoose");
const os = require("os");
const jwt = require("jsonwebtoken");

const config = require("./config");
const user = require("./routes/user.js");
const expense = require("./routes/expense.js");

const port = process.env.PORT || config.serverport;

main().catch((err) => {
  console.log(
    "Error connecting to database, please check if MongoDB is running."
  );
  console.log(err);
});

async function main() {
  await mongoose.connect(config.database);
  console.log("Connected to database...");
}

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: true }));
app.use(require("body-parser").json({ type: "*/*" }));

app.use(express.static(__dirname + "/dist"));
// use morgan to log requests to the console
app.use(morgan("dev"));

// Enable CORS from client-side
app.use(function (req, res, next) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "PUT, GET, POST, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, Access-Control-Allow-Credentials"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

// basic routes

app.get("/", function (req, res) {
  res.send(
    "Expense Watch API is running at " + os.hostname() + ":" + port + "/api"
  );
});

app.post("/register", user.signup);

// express router
const apiRoutes = express.Router();

app.use("/api", apiRoutes);

apiRoutes.post("/login", user.login);

apiRoutes.use(user.authenticate); // route middleware to authenticate and check token

// authenticated routes
apiRoutes.get("/", function (req, res) {
  res.status(201).json({ message: "Welcome to the authenticated routes!" });
});

apiRoutes.get("/user/:id", user.getuserDetails); // API returns user details

apiRoutes.put("/user/:id", user.updateUser); // API updates user details

apiRoutes.put("/password/:id", user.updatePassword); // API updates user password

apiRoutes.post("/expense/:id", expense.saveexpense); // API adds & update expense of the user

apiRoutes.delete("/expense/:id", expense.delexpense); //API removes the expense details of given expense id

apiRoutes.get("/expense/:id", expense.getexpense); // API returns expense details of given expense id

apiRoutes.post("/expense/total/:id", expense.expensetotal); // API returns expense details of given expense id

apiRoutes.post("/expense/report/:id", expense.expensereport); //API returns expense report based on user input

// kick off the server
app.listen(port);
console.log("Expense Watch app is listening at " + os.hostname() + ":" + port);
