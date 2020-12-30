const router = require("express").Router();

const User = require("../models/User");

const Joi = require("@hapi/joi");
const schemaRegister = Joi.object({
  name: Joi.string().min(6).max(255).required(),
  email: Joi.string().min(6).max(255).required().email(),
  password: Joi.string().min(6).max(1024).required(),
});

const schemaLogin = Joi.object({
  email: Joi.string().min(6).max(255).required().email(),
  password: Joi.string().min(6).max(1024).required(),
});

const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");

router.post("/login", async (req, res) => {
  // validaciones con joi
  const { error } = schemaLogin.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  //verifica el usuario
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return res
      .status(400)
      .json({ error: true, mensaje: "Usuario o password incorrecto" });

  //se valida la contraseña encriptada
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword)
    return res
      .status(400)
      .json({ error: true, mensaje: "Usuario o password incorrecto" });

  // create token
  const token = jwt.sign(
    {
      name: user.name,
      id: user._id,
    },
    process.env.TOKEN_SECRET
  );

  res.header("auth-token", token).json({
    error: null,
    data: { token },
  });

  //respuesta
  res.json({
    error: null,
    data: "exito bienvenido",
    token,
  });
});

router.post("/register", async (req, res) => {
  //validaciones de usuarios
  const { error } = schemaRegister.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  //verifica email unico
  const isEmailExits = await User.findOne({ email: req.body.email });
  if (isEmailExits) {
    return res.status(400).json({
      error: true,
      mensaje: "email ya está registrado",
    });
  }

  // hash contraseña
  const salt = await bcrypt.genSalt(10); //<--- el salt es la cantidad de veces de encriptado
  const password = await bcrypt.hash(req.body.password, salt);

  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: password,
  });

  try {
    const userDB = await user.save();
    res.json({
      error: null,
      data: userDB,
    });
  } catch (error) {
    res.status(400).json(error);
  }
});

module.exports = router;
