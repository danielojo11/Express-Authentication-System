import pool from "../../utils/db.js";
import bcrypt from "bcrypt";
import jsonwebtoken from "jsonwebtoken";

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Invalid Form Data" });
    }
    const existing = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    console.log("existing", existing);
    if (existing.rows.length === 0) {
      return res.status(404).json({ message: "Invalid Credentials" });
    }
    const hashCompare = await bcrypt.compare(
      password,
      existing.rows[0].password,
    );
    if (!hashCompare) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    const token = jsonwebtoken.sign(
      { userID: existing.rows[0].id },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
    });

    res.json({ message: "Login Successful" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Login Error" });
  }
};

export default login;
