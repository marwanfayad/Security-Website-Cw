const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// Use a simple in-memory database for demonstration purposes
const users = [];

passport.use(
	new LocalStrategy(async (username, password, done) => {
		const user = users.find((u) => u.username === username);

		if (!user) {
			console.log("Incorrect username.");
			return done(null, false, { message: "Incorrect username." });
		}

		if (!bcrypt.compareSync(password, user.password)) {
			console.log("Incorrect password.");
			return done(null, false, { message: "Incorrect password." });
		}

		return done(null, user);
	})
);

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser((id, done) => {
	const user = users.find((u) => u.id === id);
	done(null, user);
});

app.use(express.urlencoded({ extended: false }));

app.use(
	session({
		secret: "your-secret-key",
		resave: false,
		saveUninitialized: false,
	})
);
app.use(passport.initialize());
app.use(passport.session());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, "public")));

// ########################################################################################################################################
// Home

app.get("/home", (req, res) => {
	console.log("Session:", req.session);
	console.log("User:", req.user);

	if (req.isAuthenticated()) {
		res.send(
			`<h1>Welcome, ${req.user.username}!</h1><a href="/logout">Logout</a>`
		);
	} else {
		res.sendFile(path.join(__dirname, "public", "login.html"), {
			"Content-Type": "text/html",
		});
	}
});

// ########################################################################################################################################
// Login

app.get("/login", (req, res) => {
	res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post(
	"/login",
	passport.authenticate("local", {
		successRedirect: "/home",
		failureRedirect: "/login",
	})
);

// ########################################################################################################################################
// Logout

app.get("/logout", (req, res) => {
	req.logout((err) => {
		if (err) {
			return res.send("Error during logout");
		}

		res.redirect("/login");
	});
});

// ########################################################################################################################################
// Register

app.get("/register", (req, res) => {
	res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.post("/register", (req, res) => {
	const { username, password } = req.body;

	// Validate password length
	const passwordLength = password.length;
	if (passwordLength < 8 || passwordLength > 15) {
		return res.send("Password must be between 8 and 15 characters.");
	}

	// Validate if username already exists
	if (users.some((user) => user.username === username)) {
		return res.send("Username already exists. Choose a different one.");
	}

	// Hash the password
	const hashedPassword = bcrypt.hashSync(password, 10);

	// Create a new user
	const newUser = {
		id: users.length + 1,
		username: username,
		password: hashedPassword,
	};

	// Add the new user to the users array
	users.push(newUser);

	console.log("User registered successfully:", newUser);
	res.redirect("/login");
});

// ########################################################################################################################################
// Unmatched routes

app.get("*", (req, res) => {
	res.status(404).send("Not Found");
});

// ########################################################################################################################################
// Start server

const PORT = 8080;
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
