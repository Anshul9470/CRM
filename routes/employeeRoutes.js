import express from "express";
import bcrypt from "bcrypt";
import Employee from "../models/Employee.js";

const router = express.Router();

// ===== ADD EMPLOYEE (ONLY PASSWORD HASHED) =====
router.post("/add-employee", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check duplicate email (now this will WORK)
    const existing = await Employee.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const saltRounds = 10;

    // 🔐 Hash ONLY password (correct way)
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newEmp = new Employee({
      name,
      email,              // 👉 plain email store (for login & listing)
      password: hashedPassword // 👉 hashed password store
    });

    await newEmp.save();

    res.status(201).json({ message: "Employee Saved" });
  } catch (error) {
    res.status(500).json({ error: "Error saving employee" });
  }
});

// ===== EMPLOYEE LOGIN ROUTE (VERIFY HASH) =====
router.post("/employee-login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find employee by email (now works properly)
    const employee = await Employee.findOne({ email });

    if (!employee) {
      return res.status(400).json({ error: "User not found" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, employee.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Success response
    res.json({
      message: "Login successful",
      user: {
        id: employee._id,
        name: employee.name,
        email: employee.email,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Login error" });
  }
});

// ===== GET ALL EMPLOYEES =====
router.get("/employees", async (req, res) => {
  try {
    const employees = await Employee.find().select("-password"); // password hide
    res.json(employees);
  } catch (error) {
    res.status(500).json({ error: "Error fetching employees" });
  }
});

export default router;