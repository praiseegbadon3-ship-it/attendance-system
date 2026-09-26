const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const db = admin.firestore();

module.exports = async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Device-Secret");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed",
    });
  }

  try {
    const { deviceId } = req.body || {};
    const deviceSecret = req.headers["x-device-secret"];

    // Validate request
    if (!deviceId || !deviceSecret) {
      return res.status(400).json({
        success: false,
        message: "deviceId and X-Device-Secret are required",
      });
    }

    // Get device
    const deviceRef = db.collection("devices").doc(deviceId);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).json({
        success: false,
        message: "Device not found",
      });
    }

    const device = deviceSnap.data();

    // Hash supplied device secret
    const crypto = require("crypto");

    const suppliedHash = crypto
      .createHash("sha256")
      .update(deviceSecret)
      .digest("hex");

    // Verify device secret
    if (suppliedHash !== device.deviceSecretHash) {
      return res.status(401).json({
        success: false,
        message: "Invalid device secret",
      });
    }

    // No active session
    if (!device.currentSessionId || device.status !== "active") {
      return res.status(200).json({
        success: true,
        active: false,
        sessionId: null,
        startTime: null,
        endTime: null,
        message: "No active session",
      });
    }

    // Get current session
    const sessionRef = db
      .collection("sessions")
      .doc(device.currentSessionId);

    const sessionSnap = await sessionRef.get();

    if (!sessionSnap.exists) {
      return res.status(200).json({
        success: true,
        active: false,
        sessionId: null,
        startTime: null,
        endTime: null,
        message: "Session not found",
      });
    }

    const session = sessionSnap.data();

    // Check session status
    if (session.status !== "active") {
      return res.status(200).json({
        success: true,
        active: false,
        sessionId: null,
        startTime: session.startTime || null,
        endTime: session.endTime || null,
        message: "Session is not active",
      });
    }

    // Active session
    return res.status(200).json({
      success: true,
      active: true,
      sessionId: device.currentSessionId,
      courseId: session.courseId || null,
      startTime: session.startTime || null,
      endTime: session.endTime || null,
      message: "Session is active",
    });

  } catch (error) {
    console.error("deviceStatus error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
