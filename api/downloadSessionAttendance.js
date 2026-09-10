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
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).send({ error: "Method not allowed" });
  }

  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).send({ error: "Missing sessionId" });
    }

    // --- Verify auth token ---
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ")
      ? authHeader.split("Bearer ")[1]
      : null;

    if (!idToken) {
      return res.status(401).send({ error: "Missing auth token" });
    }

    try {
      await getAuth().verifyIdToken(idToken);
    } catch (err) {
      return res.status(401).send({ error: "Invalid auth token" });
    }
    // --- End auth check ---

    const sessionRef = db.collection("sessions").doc(sessionId);
    const sessionSnap = await sessionRef.get();

    if (!sessionSnap.exists) {
      return res.status(404).send({ error: "Session not found" });
    }

    const sessionData = sessionSnap.data();

    if (sessionData.status !== "closed") {
      return res.status(400).send({
        error: "Attendance can only be downloaded for completed sessions",
      });
    }

    const courseId = sessionData.courseId;
    const deviceId = sessionData.deviceId;
    const attendees = sessionData.attendees || {};

    let courseCode = "";
    let courseTitle = "";

    if (courseId) {
      const courseSnap = await db.collection("courses").doc(courseId).get();

      if (courseSnap.exists) {
        const courseData = courseSnap.data();
        courseCode = courseData.courseCode || "";
        courseTitle = courseData.courseTitle || "";
      }
    }

    // Get students belonging to this device
    let studentsByRegNo = {};

    if (deviceId) {
      const studentsSnap = await db
        .collection("students")
        .where("deviceId", "==", deviceId)
        .get();

      studentsSnap.forEach((doc) => {
        const student = doc.data();

        if (student.regNo) {
          studentsByRegNo[String(student.regNo)] = {
            fullName: student.fullName || "",
            regNo: String(student.regNo),
          };
        }
      });
    }

    const rows = [];

    rows.push(["Course Code", courseCode]);
    rows.push(["Course Title", courseTitle]);
    rows.push(["Session ID", sessionId]);
    rows.push(["Device ID", deviceId || ""]);
    rows.push([]);

    rows.push(["Reg No", "Student Name", "Attendance Time"]);

    for (const [regNo, attendanceData] of Object.entries(attendees)) {
      const student = studentsByRegNo[String(regNo)];

      let timestamp = "";

      if (attendanceData && attendanceData.timestamp) {
        const value = attendanceData.timestamp;

        if (value && typeof value.toDate === "function") {
          timestamp = value.toDate().toLocaleString();
        } else if (value) {
          timestamp = new Date(value).toLocaleString();
        }
      }

      // Prefix the registration number as an Excel text value
      const excelRegNo = `="${String(regNo).replace(/"/g, '""')}"`;

      rows.push([
        excelRegNo,
        student ? student.fullName : "Unknown Student",
        timestamp,
      ]);
    }

    if (Object.keys(attendees).length === 0) {
      rows.push(["", "No students attended this session", ""]);
    }

    const escapeCsvValue = (value) => {
      if (value === null || value === undefined) {
        return "";
      }

      const stringValue = String(value);

      if (
        stringValue.includes(",") ||
        stringValue.includes('"') ||
        stringValue.includes("\n") ||
        stringValue.includes("\r")
      ) {
        return `"${stringValue.replace(/"/g, '""')}"`;
      }

      return stringValue;
    };

    const csv = rows
      .map((row) => row.map(escapeCsvValue).join(","))
      .join("\r\n");

    const filename = `session-attendance-${sessionId}.csv`;

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );

    return res.status(200).send(csv);
  } catch (error) {
    console.error("Error in downloadSessionAttendance:", error);

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
