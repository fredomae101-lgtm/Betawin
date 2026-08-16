// server.js

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const MONGO_URI = process.env.MONGO_URI;

const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI is missing in .env");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing in .env");
  process.exit(1);
}


/* =========================================================
   SECURITY
========================================================= */

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    }
  })
);

app.use(
  cors({
    origin: process.env.CLIENT_URL || true,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));


/* =========================================================
   RATE LIMITING
========================================================= */

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later."
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many authentication attempts."
  }
});

app.use("/api", apiLimiter);


/* =========================================================
   MONGODB
========================================================= */

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected");
  })
  .catch((error) => {
    console.error("❌ MongoDB connection failed:");
    console.error(error.message);
    process.exit(1);
  });


/* =========================================================
   SCHEMAS
========================================================= */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true,
      minlength: 8
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    avatar: {
      type: String,
      default: ""
    },

    points: {
      type: Number,
      default: 0
    },

    active: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);


const gameSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    category: {
      type: String,
      required: true,
      lowercase: true
    },

    description: {
      type: String,
      default: ""
    },

    image: {
      type: String,
      default: ""
    },

    icon: {
      type: String,
      default: "🎮"
    },

    active: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);


const tournamentSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },

    sport: {
      type: String,
      required: true,
      lowercase: true
    },

    description: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "upcoming",
        "live",
        "finished",
        "cancelled"
      ],
      default: "upcoming"
    },

    teams: {
      type: Number,
      default: 0
    },

    matches: {
      type: Number,
      default: 0
    },

    startDate: {
      type: String,
      default: ""
    },

    active: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);


const resultSchema = new mongoose.Schema(
  {
    sport: {
      type: String,
      required: true,
      lowercase: true
    },

    league: {
      type: String,
      default: ""
    },

    home: {
      type: String,
      required: true
    },

    away: {
      type: String,
      required: true
    },

    homeScore: {
      type: Number,
      default: 0
    },

    awayScore: {
      type: Number,
      default: 0
    },

    status: {
      type: String,
      default: "Finished"
    },

    date: {
      type: String,
      default: ""
    },

    winner: {
      type: String,
      default: ""
    }
  },
  {
    timestamps: true
  }
);


const liveScoreSchema = new mongoose.Schema(
  {
    sport: {
      type: String,
      required: true,
      lowercase: true
    },

    league: {
      type: String,
      default: ""
    },

    home: {
      type: String,
      required: true
    },

    away: {
      type: String,
      required: true
    },

    homeScore: {
      type: Number,
      default: 0
    },

    awayScore: {
      type: Number,
      default: 0
    },

    period: {
      type: String,
      default: "LIVE"
    },

    status: {
      type: String,
      default: "LIVE"
    },

    updated: {
      type: String,
      default: "now"
    }
  },
  {
    timestamps: true
  }
);


const User = mongoose.model("User", userSchema);
const Game = mongoose.model("Game", gameSchema);
const Tournament = mongoose.model(
  "Tournament",
  tournamentSchema
);
const Result = mongoose.model(
  "Result",
  resultSchema
);
const LiveScore = mongoose.model(
  "LiveScore",
  liveScoreSchema
);


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function authenticate(req, res, next) {

  try {

    const header =
      req.headers.authorization;

    if (!header) {

      return res.status(401).json({
        success: false,
        message: "Authentication required"
      });

    }

    const parts =
      header.split(" ");

    if (
      parts.length !== 2 ||
      parts[0] !== "Bearer"
    ) {

      return res.status(401).json({
        success: false,
        message: "Invalid authorization header"
      });

    }

    const token = parts[1];

    const decoded =
      jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });

  }

}


/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

async function requireAdmin(
  req,
  res,
  next
) {

  try {

    const user =
      await User.findById(req.user.id)
        .select("role active");

    if (!user || !user.active) {

      return res.status(401).json({
        success: false,
        message: "Account unavailable"
      });

    }

    if (user.role !== "admin") {

      return res.status(403).json({
        success: false,
        message: "Admin access required"
      });

    }

    next();

  } catch (error) {

    next(error);

  }

}


/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {

  res.json({
    success: true,
    service: "Betawin API",
    status: "online",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
    timestamp: new Date().toISOString()
  });

});


/* =========================================================
   AUTH
========================================================= */

app.post(
  "/api/auth/register",
  authLimiter,
  async (req, res, next) => {

    try {

      const {
        name,
        email,
        password
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required"
        });

      }

      if (password.length < 8) {

        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 8 characters"
        });

      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const existing =
        await User.findOne({
          email: normalizedEmail
        });

      if (existing) {

        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists"
        });

      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await User.create({
          name: name.trim(),
          email: normalizedEmail,
          password: hashedPassword
        });


      const token =
        jwt.sign(
          {
            id: user._id.toString(),
            role: user.role
          },
          JWT_SECRET,
          {
            expiresIn:
              process.env.JWT_EXPIRES_IN ||
              "7d"
          }
        );


      res.status(201).json({

        success: true,

        message:
          "Account created successfully",

        token,

        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          points: user.points
        }

      });

    } catch (error) {

      next(error);

    }

  }
);


app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res, next) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Email and password are required"
        });

      }

      const user =
        await User.findOne({
          email:
            email.toLowerCase().trim()
        });

      if (!user) {

        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password"
        });

      }

      if (!user.active) {

        return res.status(403).json({
          success: false,
          message:
            "Account is disabled"
        });

      }

      const valid =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!valid) {

        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password"
        });

      }

      const token =
        jwt.sign(
          {
            id: user._id.toString(),
            role: user.role
          },
          JWT_SECRET,
          {
            expiresIn:
              process.env.JWT_EXPIRES_IN ||
              "7d"
          }
        );


      res.json({

        success: true,

        message: "Login successful",

        token,

        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          points: user.points,
          avatar: user.avatar
        }

      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  authenticate,
  async (req, res, next) => {

    try {

      const user =
        await User.findById(req.user.id)
          .select("-password");

      if (!user) {

        return res.status(404).json({
          success: false,
          message: "User not found"
        });

      }

      res.json({
        success: true,
        user
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   PROFILE
========================================================= */

app.get(
  "/api/users/profile",
  authenticate,
  async (req, res, next) => {

    try {

      const user =
        await User.findById(req.user.id)
          .select("-password");

      res.json({
        success: true,
        user
      });

    } catch (error) {

      next(error);

    }

  }
);


app.put(
  "/api/users/profile",
  authenticate,
  async (req, res, next) => {

    try {

      const {
        name,
        avatar
      } = req.body;

      const updates = {};

      if (name)
        updates.name =
          name.trim();

      if (avatar !== undefined)
        updates.avatar =
          avatar;

      const user =
        await User.findByIdAndUpdate(
          req.user.id,
          updates,
          {
            new: true,
            runValidators: true
          }
        )
        .select("-password");

      res.json({
        success: true,
        user
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   GAMES
========================================================= */

app.get(
  "/api/games",
  authenticate,
  async (req, res, next) => {

    try {

      const games =
        await Game.find({
          active: true
        })
        .sort({
          createdAt: -1
        })
        .lean();

      res.json({
        success: true,
        games
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   SPORTS
========================================================= */

app.get(
  "/api/sports",
  authenticate,
  async (req, res, next) => {

    try {

      const [
        tournaments,
        results
      ] = await Promise.all([

        Tournament.find({
          active: true
        })
        .sort({
          startDate: 1
        })
        .lean(),

        Result.find()
          .sort({
            createdAt: -1
          })
          .limit(50)
          .lean()

      ]);


      res.json({
        success: true,
        tournaments,
        results
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   LIVE SCORES
========================================================= */

app.get(
  "/api/sports/live-scores",
  authenticate,
  async (req, res, next) => {

    try {

      const scores =
        await LiveScore.find({
          status: {
            $regex: /^live$/i
          }
        })
        .sort({
          updatedAt: -1
        })
        .lean();

      res.json({
        success: true,
        scores
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   TOURNAMENTS
========================================================= */

app.get(
  "/api/tournaments",
  authenticate,
  async (req, res, next) => {

    try {

      const tournaments =
        await Tournament.find({
          active: true
        })
        .sort({
          createdAt: -1
        })
        .lean();

      res.json({
        success: true,
        tournaments
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   RESULTS
========================================================= */

app.get(
  "/api/results",
  authenticate,
  async (req, res, next) => {

    try {

      const results =
        await Result.find()
          .sort({
            createdAt: -1
          })
          .limit(100)
          .lean();

      res.json({
        success: true,
        results
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   LEADERBOARD
========================================================= */

app.get(
  "/api/leaderboard",
  authenticate,
  async (req, res, next) => {

    try {

      const players =
        await User.find({
          active: true
        })
        .select(
          "name avatar points"
        )
        .sort({
          points: -1
        })
        .limit(100)
        .lean();


      const leaderboard =
        players.map(
          (player, index) => ({

            rank: index + 1,

            name: player.name,

            avatar: player.avatar,

            points: player.points,

            position:
              `${index + 1}${getOrdinal(index + 1)}`

          })
        );


      res.json({
        success: true,
        players: leaderboard
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ADMIN — GAMES
========================================================= */

app.post(
  "/api/admin/games",
  authenticate,
  requireAdmin,
  async (req, res, next) => {

    try {

      const game =
        await Game.create(req.body);

      res.status(201).json({
        success: true,
        game
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ADMIN — TOURNAMENTS
========================================================= */

app.post(
  "/api/admin/tournaments",
  authenticate,
  requireAdmin,
  async (req, res, next) => {

    try {

      const tournament =
        await Tournament.create(
          req.body
        );

      res.status(201).json({
        success: true,
        tournament
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ADMIN — RESULTS
========================================================= */

app.post(
  "/api/admin/results",
  authenticate,
  requireAdmin,
  async (req, res, next) => {

    try {

      const result =
        await Result.create(
          req.body
        );

      res.status(201).json({
        success: true,
        result
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ADMIN — LIVE SCORES
========================================================= */

app.post(
  "/api/admin/live-scores",
  authenticate,
  requireAdmin,
  async (req, res, next) => {

    try {

      const score =
        await LiveScore.create(
          req.body
        );

      res.status(201).json({
        success: true,
        score
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );

});


/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      success: false,
      message: "API endpoint not found"
    });

  }
);


/* =========================================================
   404 FRONTEND
========================================================= */

app.use(
  (req, res) => {

    res.status(404).send(
      "Page not found"
    );

  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      error
    );


    if(error.code === 11000){

      return res.status(409).json({
        success: false,
        message:
          "A record with this information already exists"
      });

    }


    if(
      error.name ===
      "ValidationError"
    ){

      return res.status(400).json({
        success: false,
        message:
          "Invalid request data"
      });

    }


    res.status(500).json({

      success: false,

      message:
        process.env.NODE_ENV ===
        "production"
          ? "Internal server error"
          : error.message

    });

  }
);


/* =========================================================
   HELPERS
========================================================= */

function getOrdinal(number){

  if(
    number % 100 >= 11 &&
    number % 100 <= 13
  ){

    return "th";

  }

  switch(number % 10){

    case 1:
      return "st";

    case 2:
      return "nd";

    case 3:
      return "rd";

    default:
      return "th";

  }

}


/* =========================================================
   START SERVER
========================================================= */

const server =
  app.listen(
    PORT,
    () => {

      console.log("");
      console.log(
        "================================"
      );
      console.log(
        "      BETAWIN API SERVER"
      );
      console.log(
        "================================"
      );
      console.log(
        `🚀 Port: ${PORT}`
      );
      console.log(
        `🌐 http://localhost:${PORT}`
      );
      console.log(
        "🔐 JWT authentication enabled"
      );
      console.log(
        "🛡️ Security middleware enabled"
      );
      console.log(
        "🎮 Games API enabled"
      );
      console.log(
        "⚽ Sports API enabled"
      );
      console.log(
        "🏆 Tournaments API enabled"
      );
      console.log(
        "📊 Results API enabled"
      );
      console.log(
        "🔴 Live scores API enabled"
      );
      console.log(
        "🥇 Leaderboard API enabled"
      );
      console.log(
        "================================"
      );
      console.log("");

    }
  );


/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(signal){

  console.log(
    `\n${signal} received. Shutting down...`
  );

  server.close(async () => {

    await mongoose.connection.close();

    console.log(
      "✅ Server closed"
    );

    process.exit(0);

  });

}


process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);
