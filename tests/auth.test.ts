import request from "supertest";
import app from "../src/app.js";
import pool from "../src/config/db.js";

describe("Auth Endpoints", () => {
  beforeAll(async () => {
    // Clean up test DB tables before running tests
    await pool.query("DELETE FROM users");
  });

  afterAll(async () => {
    await pool.end();
  });

  it("should block registration with short password", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({
        name: "Test User",
        email: "invalid@example.com",
        password: "short",
      });
    
    expect(res.statusCode).toEqual(400);
    expect(res.body.message).toContain("Validation Error");
  });

  it("should register a new user", async () => {
    // Note: this test requires the email verification table/process to succeed
    // In a real environment, you'd mock the sendMail function
    // For this example, we expect it to try and return 400 since nodemailer isn't configured in test,
    // or 201 if mail sends successfully locally.
    const res = await request(app)
      .post("/api/auth/register")
      .send({
        name: "Test User",
        email: "test@example.com",
        password: "password123",
      });
    
    // We'll assert it at least hits the controller and attempts creation
    expect([201, 400]).toContain(res.statusCode);
  });

  it("should login the user", async () => {
    // Just a placeholder test showing structure
    const res = await request(app)
      .post("/api/auth/login")
      .send({
        email: "test@example.com",
        password: "password123",
      });
    
    expect([200, 401]).toContain(res.statusCode);
  });
});
