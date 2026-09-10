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
    const { courseId } = req.body;

    if (!courseId) {
      return res.status(400).send({ error: "Missing courseId" });
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

    // Get course information
    const courseRef = db.collection("courses").doc(courseId);
    const courseSnap = await courseRef.get();

    if (!courseSnap.exists) {
      return res.status(404).send({ error: "Course not found" });
    }

    const courseData = courseSnap.data();

    const courseCode = courseData.courseCode || "";
    const courseTitle = courseData.courseTitle || "";
    const level = courseData.level || "";

    // Get every student at this course's level.
    // This follows the current project rule that all students
    // at a level take every course at that level.
    const studentsSnap = await db
      .collection("students")
      .where("level", "==", level)
      .get();

    const rows = [];

    // Report information
    rows.push(["Course Code", courseCode]);
    rows.push(["Course Title", courseTitle]);
    rows.push(["Level", level]);
    rows.push(["Course ID", courseId]);
    rows.push([]);

    // CSV headers
    rows.push([
      "Reg No",
      "Student Name",
      "Present",
      "Total Sessions",
      "Attendance Percentage",
    ]);

    // Add every student, including students with no attendance yet.
    studentsSnap.forEach((doc) => {
      const student = doc.data();

      const regNo = student.regNo || "";
      const fullName = student.fullName || "";

      const attendanceStats =
        (student.attendanceStats &&
          student.attendanceStats[courseId]) ||
        {};

      const present = attendanceStats.present || 0;
      const total = attendanceStats.total || 0;
      const percentage = attendanceStats.percentage || 0;

      rows.push([
        regNo,
        fullName,
        present,
        total,
        `${percentage}%`,
      ]);
    });

    // Escape CSV values safely
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

    const filename = `course-attendance-${courseCode || courseId}.csv`;

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );

    return res.status(200).send(csv);
  } catch (error) {
    console.error("Error in downloadCourseAttendance:", error);

    return res.status(500).send({
      error: "Internal server error",
    });
  }
};
