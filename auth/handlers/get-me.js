import pool from "../../utils/db.js";

const getMe = async (req, res) => {
  try {
    const user = await pool.query(
      "SELECT id, name, email FROM users WHERE id = $1",
      [req.user.userID],
    );
    res.status(200).json({ user: user.rows[0] });
  } catch (error) {
    res.status(500).json({ error: "Server Error" });
  }
};

export default getMe;
