const crypto = require("crypto");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

// Initialize Firebase Admin only once
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const db = getFirestore();

function hashSecret(secret) {
  return crypto
    .createHash("sha256")
    .update(secret)
    .digest("hex");
}

module.exports = async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  // Preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).send({
      error: "Method not allowed",
    });
  }

  try {
    const {
      deviceId,
      deviceSecret,
      fingerprintId,
      regNo,
      fullName,
      department,
      level,
    } = req.body;

    // -----------------------------
    // Validate required information
    // -----------------------------

    if (
      !deviceId ||
      !deviceSecret ||
      fingerprintId === undefined ||
      !regNo ||
      !fullName ||
      !department ||
      level === undefined
    ) {
      return res.status(400).send({
        error: "Missing required fields",
      });
    }

    // -----------------------------
    // Validate fingerprint ID
    // -----------------------------

    const parsedFingerprintId = Number(fingerprintId);

    if (
      !Number.isInteger(parsedFingerprintId) ||
      parsedFingerprintId < 1
    ) {
      return res.status(400).send({
        error: "Invalid fingerprint ID",
      });
    }

    // -----------------------------
    // Validate level
    // -----------------------------

    const parsedLevel = Number(level);

    if (!Number.isInteger(parsedLevel)) {
      return res.status(400).send({
        error: "Invalid level",
      });
    }

    // -----------------------------
    // Find device
    // -----------------------------

    const deviceRef = db.collection("devices").doc(deviceId);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).send({
        error: "Device not found",
      });
    }

    const deviceData = deviceSnap.data();

    // -----------------------------
    // Check device secret
    // -----------------------------

    if (!deviceData.deviceSecretHash) {
      return res.status(500).send({
        error: "Device authentication is not configured",
      });
    }

    const suppliedSecretHash = hashSecret(deviceSecret);

    if (suppliedSecretHash !== deviceData.deviceSecretHash) {
      return res.status(403).send({
        error: "Device authentication failed",
      });
    }

    // -----------------------------
    // Make sure fingerprint ID
    // isn't already assigned
    // -----------------------------

    const studentDocId = `${deviceId}_${parsedFingerprintId}`;

    const studentRef = db
      .collection("students")
      .doc(studentDocId);

    const existingStudent = await studentRef.get();

    if (existingStudent.exists) {
      return res.status(409).send({
        error: "Fingerprint ID is already assigned to a student",
      });
    }

    // -----------------------------
    // Make sure registration number
    // isn't already being used
    // -----------------------------

    const existingRegNo = await db
      .collection("students")
      .where("regNo", "==", String(regNo).trim())
      .limit(1)
      .get();

    if (!existingRegNo.empty) {
      return res.status(409).send({
        error: "Registration number is already registered",
      });
    }

    // -----------------------------
    // Create student record
    // -----------------------------

    const studentData = {
      regNo: String(regNo).trim(),
      fullName: String(fullName).trim(),
      department: String(department).trim(),
      level: parsedLevel,
      deviceId: deviceId,
      fingerprintId: parsedFingerprintId,
      attendanceStats: {},
    };

    await studentRef.set(studentData);

    // -----------------------------
    // Success
    // -----------------------------

    return res.status(201).send({
      success: true,
      message: "Student enrolled successfully",
      studentId: studentDocId,
      fingerprintId: parsedFingerprintId,
      regNo: studentData.regNo,
    });

  } catch (error) {
    console.error("Error in enrollStudent:", error);

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
