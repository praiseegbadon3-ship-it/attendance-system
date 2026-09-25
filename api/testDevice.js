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
        error: "Device secret hash not configured",
      });
    }

    const suppliedHash = hashSecret(deviceSecret);

    if (suppliedHash !== deviceData.deviceSecretHash) {
      return res.status(403).send({
        error: "Device authentication failed",
      });
    }

    return res.status(200).send({
      success: true,
      message: "Device authenticated successfully",
      deviceId,
    });

  } catch (error) {
    console.error("Error in testDevice:", error);

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
