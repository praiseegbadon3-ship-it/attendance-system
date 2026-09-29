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
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Device-Secret"
  );

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

    // ------------------------------------------------------------
    // DEVICE HEARTBEAT
    // ------------------------------------------------------------
    // The Wemos reaches this endpoint repeatedly.
    // A successful authenticated request means the physical device
    // is currently communicating with the backend.

    const now = new Date();

    await deviceRef.update({
      lastSeen: admin.firestore.Timestamp.fromDate(now),
    });

    // ------------------------------------------------------------
    // NO ACTIVE SESSION
    // ------------------------------------------------------------

    if (!device.currentSessionId || device.status !== "active") {
      return res.status(200).json({
        success: true,
        active: false,
        attendanceReady: false,
        sessionId: null,
        startTime: null,
        endTime: null,
        serverTime: now.toISOString(),
        lastSeen: now.toISOString(),
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
        attendanceReady: false,
        sessionId: null,
        startTime: null,
        endTime: null,
        serverTime: now.toISOString(),
        lastSeen: now.toISOString(),
        message: "Session not found",
      });
    }

    const session = sessionSnap.data();

    // Check session status
    if (session.status !== "active") {
      return res.status(200).json({
        success: true,
        active: false,
        attendanceReady: false,
        sessionId: null,
        startTime: session.startTime || null,
        endTime: session.endTime || null,
        serverTime: now.toISOString(),
        lastSeen: now.toISOString(),
        message: "Session is not active",
      });
    }

    // ------------------------------------------------------------
    // SERVER-TIME ATTENDANCE READINESS
    // ------------------------------------------------------------

    let attendanceReady = false;

    if (
      session.startTime &&
      typeof session.startTime.toDate === "function"
    ) {
      const startTime = session.startTime.toDate();

      attendanceReady = now >= startTime;
    }

    // ------------------------------------------------------------
    // ACTIVE SESSION
    // ------------------------------------------------------------

    return res.status(200).json({
      success: true,
      active: true,
      attendanceReady: attendanceReady,
      sessionId: device.currentSessionId,
      courseId: session.courseId || null,
      startTime: session.startTime || null,
      endTime: session.endTime || null,
      serverTime: now.toISOString(),
      lastSeen: now.toISOString(),
      message: attendanceReady
        ? "Attendance is ready"
        : "Session authorized, waiting for start time",
    });
  } catch (error) {
    console.error("deviceStatus error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
