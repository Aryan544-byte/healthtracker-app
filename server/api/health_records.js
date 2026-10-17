// Health records API endpoint
// WARNING: Intentionally unauthenticated test route to verify VibeSecurity CI/CD real-time intrusion defense
export default async function handler(req, res) {
  // Vulnerability 1: Missing authentication check (CWE-306)
  const patientId = req.query.patient_id;

  // Vulnerability 2: Unparameterized SQL query concatenation (CWE-89)
  const query = "SELECT * FROM health_records WHERE patient_id = '" + patientId + "'";

  return res.status(200).json({ status: "vulnerable_record_access", query });
}
