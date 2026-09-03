const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

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
  if (req.method !== "POST") {
    return res.status(405).send({ error: "Method not allowed" });
  }

  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).send({ error: "Missing sessionId" });
    }

    // --- Verify auth token (lecturer must be signed in) ---
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ? authHeader.split("Bearer ")[1] : null;

    if (!idToken) {
      return res.status(401).send({ error: "Missing auth token" });
    }

    try {
      await getAuth().verifyIdToken(idToken);
    } catch (err) {
      return res.status(401).send({ error: "Invalid auth token" });
    }
    // --- end auth check ---

    const sessionRef = db.collection("sessions").doc(sessionId);
    const sessionSnap = await sessionRef.get();

    if (!sessionSnap.exists) {
      return res.status(404).send({ error: "Session not found" });
    }

    const sessionData = sessionSnap.data();

    if (sessionData.status === "closed") {
      return res.status(400).send({ error: "Session already closed" });
    }

    const courseId = sessionData.courseId;
    const deviceId = sessionData.deviceId;
    const attendees = sessionData.attendees || {};

    // 1. Close the session
    await sessionRef.update({ status: "closed" });

    // 2. Reset the device back to idle
    if (deviceId) {
      await db.collection("devices").doc(deviceId).update({
        status: "idle",
        currentSessionId: null,
      });
    }

    // 3. Update attendance stats for every enrolled student
    const studentsSnap = await db
      .collection("students")
      .where("enrolledCourses", "array-contains", courseId)
      .get();

    const batch = db.batch();

    studentsSnap.forEach((doc) => {
      const student = doc.data();
      const regNo = student.regNo;
      const wasPresent = Object.prototype.hasOwnProperty.call(attendees, regNo);

      const currentStats = (student.attendanceStats && student.attendanceStats[courseId]) || {
        present: 0,
        total: 0,
        percentage: 0,
      };

      const newTotal = currentStats.total + 1;
      const newPresent = currentStats.present + (wasPresent ? 1 : 0);
      const newPercentage = Math.round((newPresent / newTotal) * 100);

      batch.update(doc.ref, {
        [`attendanceStats.${courseId}`]: {
          present: newPresent,
          total: newTotal,
          percentage: newPercentage,
        },
      });
    });

    await batch.commit();

    return res.status(200).send({ success: true, studentsUpdated: studentsSnap.size });

  } catch (error) {
    console.error("Error in endSession:", error);
    return res.status(500).send({ error: "Internal server error" });
  }
};
