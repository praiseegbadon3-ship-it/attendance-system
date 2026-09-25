const crypto = require("crypto");

const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

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
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).send({
      error: "Method not allowed",
    });
  }

  try {
    const { deviceId, deviceSecret } = req.body;

    if (!deviceId || !deviceSecret) {
      return res.status(400).send({
        error: "Missing deviceId or deviceSecret",
      });
    }

    const deviceRef = db.collection("devices").doc(deviceId);
    const deviceSnap = await deviceRef.get();

    if (!deviceSnap.exists) {
      return res.status(404).send({
        error: "Device not found",
      });
    }

    const deviceData = deviceSnap.data();

    if (!deviceData.deviceSecretHash) {
      return res.status(500).send({
        error: "Device authentication is not configured",
      });
    }

    const suppliedHash = hashSecret(deviceSecret);

    if (suppliedHash !== deviceData.deviceSecretHash) {
      return res.status(403).send({
        error: "Device authentication failed",
      });
    }

    // Do not allow destructive reset during an active attendance session.
    if (
      deviceData.status === "active" ||
      deviceData.currentSessionId
    ) {
      return res.status(409).send({
        error: "Cannot reset device while an attendance session is active",
      });
    }

    const studentsSnap = await db
      .collection("students")
      .where("deviceId", "==", deviceId)
      .get();

    if (studentsSnap.empty) {
      return res.status(200).send({
        success: true,
        message: "No students found for this device",
        deletedStudents: 0,
      });
    }

    const batch = db.batch();

    studentsSnap.forEach((studentDoc) => {
      batch.delete(studentDoc.ref);
    });

    await batch.commit();

    return res.status(200).send({
      success: true,
      message: "All students for this device have been deleted",
      deletedStudents: studentsSnap.size,
    });

  } catch (error) {
    console.error("Error in resetDeviceData:", error);

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
