require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();

const PORT = process.env.PORT || 4322;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

app.use(express.json());


// =============================
// MongoDB ulanish
// =============================

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB ulandi');
  })
  .catch((error) => {
    console.log('❌ MongoDB ulanishda xatolik:');
    console.log(error.message);
  });


// =============================
// USER SCHEMA
// =============================

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    passwordHash: {
      type: String,
      required: true,
    },

    firstName: {
      type: String,
      required: true,
      trim: true,
    },

    lastName: {
      type: String,
      required: true,
      trim: true,
    },

    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },

    phone: {
      type: String,
      default: null,
    },

    avatarUrl: {
      type: String,
      default: null,
    },

    dateOfBirth: {
      type: Date,
      default: null,
    },

    gender: {
      type: String,
      enum: ['male', 'female'],
      default: null,
    },

    address: {
      city: {
        type: String,
        default: null,
      },

      district: {
        type: String,
        default: null,
      },

      country: {
        type: String,
        default: 'Uzbekistan',
      },
    },

    isVerified: {
      type: Boolean,
      default: false,
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model('User', userSchema);


// =============================
// PUBLIC USER
// =============================

function publicUser(user) {
  const obj = user.toObject();

  delete obj.passwordHash;
  delete obj.__v;

  return obj;
}


// =============================
// AUTH MIDDLEWARE
// =============================

function requireAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({
      message: 'Bearer token yuboring.',
    });
  }

  const token = authorization.slice(7);

  try {
    req.auth = jwt.verify(token, JWT_SECRET);

    next();
  } catch (error) {
    return res.status(401).json({
      message: 'Token yaroqsiz yoki muddati tugagan.',
    });
  }
}


// =============================
// SWAGGER
// =============================

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.3',

    info: {
      title: 'Users Authentication API',
      version: '1.0.0',
      description: 'Register, Login va JWT Authentication API',
    },

    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Local server',
      },
      {
        url:'https://three122.onrender.com',
        description:"Global server"
      }
    ],

    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },

      schemas: {
        RegisterRequest: {
          type: 'object',

          required: [
            'email',
            'password',
            'firstName',
            'lastName',
            'username',
          ],

          properties: {
            email: {
              type: 'string',
              example: 'behruz@example.com',
            },

            password: {
              type: 'string',
              example: 'Behruz123',
            },

            firstName: {
              type: 'string',
              example: 'Behruz',
            },

            lastName: {
              type: 'string',
              example: 'Sotimboyev',
            },

            username: {
              type: 'string',
              example: 'behruz_dev',
            },

            phone: {
              type: 'string',
              example: '+998901234567',
            },

            gender: {
              type: 'string',
              example: 'male',
            },
          },
        },

        LoginRequest: {
          type: 'object',

          required: ['email', 'password'],

          properties: {
            email: {
              type: 'string',
              example: 'behruz@example.com',
            },

            password: {
              type: 'string',
              example: 'Behruz123',
            },
          },
        },
      },
    },
  },

  apis: ['./server.js'],
});

app.use(
  '/api-docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec)
);


// =============================
// HOME
// =============================

/**
 * @swagger
 * /:
 *   get:
 *     summary: API holatini tekshirish
 *     responses:
 *       200:
 *         description: API ishlamoqda
 */

app.get('/', (req, res) => {
  res.json({
    message: 'API ishlayapti',
    endpoints: [
      'POST /register',
      'POST /login',
      'GET /me',
    ],
  });
});


// =============================
// REGISTER
// =============================

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Yangi foydalanuvchi yaratish
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *     responses:
 *       201:
 *         description: User muvaffaqiyatli yaratildi
 *       400:
 *         description: Ma'lumotlar noto'g'ri
 *       409:
 *         description: Email yoki username mavjud
 */

app.post('/register', async (req, res) => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      username,
      phone,
      avatarUrl,
      dateOfBirth,
      gender,
      address,
    } = req.body;


    // 1. Validation
    if (
      !email ||
      !password ||
      !firstName ||
      !lastName ||
      !username
    ) {
      return res.status(400).json({
        message:
          'email, password, firstName, lastName va username majburiy.',
      });
    }


    // 2. Password tekshirish
    if (password.length < 6) {
      return res.status(400).json({
        message: 'Password kamida 6 ta belgidan iborat bo‘lishi kerak.',
      });
    }


    // 3. Email mavjudligini tekshirish
    const existingEmail = await User.findOne({
      email: email.toLowerCase(),
    });

    if (existingEmail) {
      return res.status(409).json({
        message: 'Bu email bilan foydalanuvchi mavjud.',
      });
    }


    // 4. Username mavjudligini tekshirish
    const existingUsername = await User.findOne({
      username,
    });

    if (existingUsername) {
      return res.status(409).json({
        message: 'Bu username band.',
      });
    }


    // 5. Password hash
    const passwordHash = await bcrypt.hash(
      password,
      10
    );


    // 6. MongoDB ga user yaratish
    const user = await User.create({
      email: email.toLowerCase(),
      passwordHash,
      firstName,
      lastName,
      username,
      phone,
      avatarUrl,
      dateOfBirth,
      gender,
      address,
    });


    // 7. Token yaratish
    const accessToken = jwt.sign(
      {
        sub: user._id.toString(),
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRES_IN,
      }
    );


    // 8. Response
    res.status(201).json({
      message: 'Ro‘yxatdan muvaffaqiyatli o‘tildi.',

      tokenType: 'Bearer',

      accessToken,

      expiresIn: JWT_EXPIRES_IN,

      user: publicUser(user),
    });

  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: 'Server xatosi.',
    });
  }
});


// =============================
// LOGIN
// =============================

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login qilish va JWT token olish
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login muvaffaqiyatli
 *       400:
 *         description: Email yoki password yuborilmagan
 *       401:
 *         description: Email yoki password xato
 */

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;


    if (!email || !password) {
      return res.status(400).json({
        message: 'email va password majburiy.',
      });
    }


    const user = await User.findOne({
      email: email.toLowerCase(),
    });


    if (!user) {
      return res.status(401).json({
        message: 'Email yoki password xato.',
      });
    }


    const passwordCorrect = await bcrypt.compare(
      password,
      user.passwordHash
    );


    if (!passwordCorrect) {
      return res.status(401).json({
        message: 'Email yoki password xato.',
      });
    }


    if (!user.isActive) {
      return res.status(403).json({
        message: 'Foydalanuvchi faol emas.',
      });
    }


    user.lastLoginAt = new Date();

    await user.save();


    const accessToken = jwt.sign(
      {
        sub: user._id.toString(),
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRES_IN,
      }
    );


    res.json({
      message: 'Login muvaffaqiyatli.',

      tokenType: 'Bearer',

      accessToken,

      expiresIn: JWT_EXPIRES_IN,

      user: publicUser(user),
    });

  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: 'Server xatosi.',
    });
  }
});


// =============================
// GET ME
// =============================

/**
 * @swagger
 * /me:
 *   get:
 *     summary: Hozirgi foydalanuvchini olish
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User ma'lumotlari
 *       401:
 *         description: Token mavjud emas
 *       404:
 *         description: User topilmadi
 */

app.get('/me', requireAuth, async (req, res) => {
  try {

    const user = await User.findById(req.auth.sub);


    if (!user) {
      return res.status(404).json({
        message: 'Foydalanuvchi topilmadi.',
      });
    }


    res.json({
      user: publicUser(user),
    });

  } catch (error) {

    res.status(500).json({
      message: 'Server xatosi.',
    });

  }
});


// =============================
// 404
// =============================

app.use((req, res) => {
  res.status(404).json({
    message: 'Route topilmadi.',
  });
});


// =============================
// SERVER
// =============================

app.listen(PORT, () => {
  console.log(
    `🚀 Server http://localhost:${PORT} da ishlayapti`
  );

  console.log(
    `📚 Swagger http://localhost:${PORT}/api-docs`
  );
});