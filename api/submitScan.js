const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

// Initialize Firebase Admin only once (Vercel reuses warm instances)
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

module.exports = async (req, res) => {
  // Allow requests from any origin (needed for browser-based testing)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle the browser's preflight check
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).send({ error: "Method not allowed" });
  }

  try {
    const { fingerprintId, timestamp, deviceId } = req.body;

    if (!fingerprintId || !timestamp || !deviceId) {
      return res.status(400).send({ error: "Missing required fields" });
    }

    // --- Verify auth token ---
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ? authHeader.split("Bearer ")[1] : null;

    if (!idToken) {
      return res.status(401).send({ error: "Missing auth token" });
    }

    let callerUid;
    try {
      const decoded = await getAuth().verifyIdToken(idToken);
      callerUid = decoded.uid;
    } catch (err) {
      return res.status(401).send({ error: "Invalid auth token" });
    }
    // --- end auth check ---

    const deviceRef = db.collection("devices").doc(deviceId);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).send({ error: "Device not found" });
    }

    const deviceData = deviceSnap.data();

    if (deviceData.authUid !== callerUid) {
      return res.status(403).send({ error: "Caller not authorized for this device" });
    }

    if (deviceData.status !== "active" || !deviceData.currentSessionId) {
      return res.status(400).send({ error: "No active session on this device" });
    }

    const sessionId = deviceData.currentSessionId;

    const studentDocId = `${deviceId}_${fingerprintId}`;
    const studentRef = db.collection("students").doc(studentDocId);
    const studentSnap = await studentRef.get();

    if (!studentSnap.exists) {
      return res.status(404).send({ error: "Student not found for this fingerprint", debug_lookedFor: studentDocId });
    }

    const regNo = studentSnap.data().regNo;

    const sessionRef = db.collection("sessions").doc(sessionId);
    const sessionSnap = await sessionRef.get();

    if (!sessionSnap.exists) {
      return res.status(404).send({ error: "Session not found" });
    }

    const sessionData = sessionSnap.data();

    if (sessionData.status !== "active") {
      return res.status(400).send({ error: "Session is not active" });
    }

    const scanTime = new Date(timestamp);
    const startTime = sessionData.startTime.toDate();
    const endTime = sessionData.endTime.toDate();

    if (scanTime < startTime || scanTime > endTime) {
      return res.status(400).send({ error: "Scan outside session time window" });
    }

    await sessionRef.update({
      [`attendees.${regNo}`]: { timestamp: scanTime },
    });

    return res.status(200).send({ success: true, regNo });

  } catch (error) {
    console.error("Error in submitScan:", error);
    return res.status(500).send({ error: "Internal server error" });
  }
};
