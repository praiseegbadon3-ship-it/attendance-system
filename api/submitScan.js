const crypto = require("crypto");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

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
  res.setHeader(
    "Access-Control-Allow-Methods",
    "POST, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Device-Secret"
  );

  // Handle preflight
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
      fingerprintId,
      timestamp,
      deviceId,
    } = req.body;

    // Validate request body
    if (
      fingerprintId === undefined ||
      !timestamp ||
      !deviceId
    ) {
      return res.status(400).send({
        error: "Missing required fields",
      });
    }

    /*
     * --------------------------------------------------
     * AUTHENTICATION
     *
     * Two supported methods:
     *
     * 1. Lecturer/browser:
     *    Authorization: Bearer <Firebase ID token>
     *
     * 2. Wemos:
     *    X-Device-Secret: <device secret>
     * --------------------------------------------------
     */

    const authHeader =
      req.headers.authorization || "";

    const deviceSecret =
      req.headers["x-device-secret"] || "";

    let authenticationMethod = null;
    let callerUid = null;

    // -----------------------------------------------
    // METHOD 1: Firebase ID TOKEN
    // -----------------------------------------------

    if (authHeader.startsWith("Bearer ")) {
      const idToken = authHeader.substring(7);

      try {
        const decoded = await getAuth().verifyIdToken(idToken);

        callerUid = decoded.uid;
        authenticationMethod = "firebase";
      } catch (error) {
        return res.status(401).send({
          error: "Invalid auth token",
        });
      }
    }

    // -----------------------------------------------
    // METHOD 2: DEVICE SECRET
    // -----------------------------------------------

    else if (deviceSecret) {
      authenticationMethod = "device";
    }

    // -----------------------------------------------
    // NO AUTHENTICATION
    // -----------------------------------------------

    else {
      return res.status(401).send({
        error: "Missing authentication",
      });
    }

    // -----------------------------------------------
    // GET DEVICE
    // -----------------------------------------------

    const deviceRef = db
      .collection("devices")
      .doc(deviceId);

    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).send({
        error: "Device not found",
      });
    }

    const deviceData = deviceSnap.data();

    // -----------------------------------------------
    // VERIFY DEVICE AUTHENTICATION
    // -----------------------------------------------

    if (authenticationMethod === "firebase") {
      if (deviceData.authUid !== callerUid) {
        return res.status(403).send({
          error: "Caller not authorized for this device",
        });
      }
    }

    if (authenticationMethod === "device") {
      if (!deviceData.deviceSecretHash) {
        return res.status(500).send({
          error: "Device authentication is not configured",
        });
      }

      const suppliedSecretHash =
        hashSecret(deviceSecret);

      if (
        suppliedSecretHash !==
        deviceData.deviceSecretHash
      ) {
        return res.status(403).send({
          error: "Device authentication failed",
        });
      }
    }

    // -----------------------------------------------
    // CHECK DEVICE SESSION
    // -----------------------------------------------

    if (
      deviceData.status !== "active" ||
      !deviceData.currentSessionId
    ) {
      return res.status(400).send({
        error: "No active session on this device",
      });
    }

    const sessionId =
      deviceData.currentSessionId;

    // -----------------------------------------------
    // FIND STUDENT USING DEVICE + FINGERPRINT ID
    // -----------------------------------------------

    const studentDocId =
      `${deviceId}_${fingerprintId}`;

    const studentRef = db
      .collection("students")
      .doc(studentDocId);

    const studentSnap = await studentRef.get();

    if (!studentSnap.exists) {
      return res.status(404).send({
        error: "Student not found for this fingerprint",
      });
    }

    const studentData = studentSnap.data();

    const regNo = studentData.regNo;

    // -----------------------------------------------
    // GET SESSION
    // -----------------------------------------------

    const sessionRef = db
      .collection("sessions")
      .doc(sessionId);

    const sessionSnap = await sessionRef.get();

    if (!sessionSnap.exists) {
      return res.status(404).send({
        error: "Session not found",
      });
    }

    const sessionData = sessionSnap.data();

    // -----------------------------------------------
    // CHECK SESSION STATUS
    // -----------------------------------------------

    if (sessionData.status !== "active") {
      return res.status(400).send({
        error: "Session is not active",
      });
    }

    // -----------------------------------------------
    // CHECK SCAN TIME
    // -----------------------------------------------

    const scanTime = new Date(timestamp);

    if (isNaN(scanTime.getTime())) {
      return res.status(400).send({
        error: "Invalid timestamp",
      });
    }

    const startTime =
      sessionData.startTime.toDate();

    const endTime =
      sessionData.endTime.toDate();

    if (
      scanTime < startTime ||
      scanTime > endTime
    ) {
      return res.status(400).send({
        error: "Scan outside session time window",
      });
    }

    // -----------------------------------------------
    // RECORD ATTENDANCE
    // -----------------------------------------------

    await sessionRef.update({
      [`attendees.${regNo}`]: {
        timestamp: scanTime,
      },
    });

    // -----------------------------------------------
    // SUCCESS
    // -----------------------------------------------

    return res.status(200).send({
      success: true,
      regNo,
      fingerprintId: Number(fingerprintId),
      deviceId,
      sessionId,
      message: "Attendance recorded successfully",
    });

  } catch (error) {
    console.error(
      "Error in submitScan:",
      error
    );

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
