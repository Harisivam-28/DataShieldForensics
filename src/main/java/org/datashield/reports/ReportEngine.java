package org.datashield.reports;

import org.datashield.database.Database;
import org.datashield.integrity.IntegrityEngine;
import org.datashield.model.Report;
import org.datashield.model.VerificationResult;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public class ReportEngine {

    public static Map<String, Object> generateReport(String caseId, String reportType, String format, String user) {
        if (reportType == null || reportType.isBlank()) {
            reportType = "Forensic Recovery Report";
        }
        if (format == null || format.isBlank()) {
            format = "JSON";
        }

        Database db = Database.getInstance();
        Map<String, Object> c = db.getById("cases", caseId);
        if (c == null) {
            c = Database.createMap("id", caseId, "name", "Forensic Case", "investigator", user != null ? user : "Investigator", "organization", "Cyber Unit");
        }

        List<Map<String, Object>> evidence = db.get("evidence").stream().filter(e -> caseId.equals(e.get("caseId"))).toList();
        List<Map<String, Object>> recoveredFiles = db.get("recoveredFiles").stream().filter(r -> caseId.equals(r.get("caseId"))).toList();
        List<Map<String, Object>> auditLogs = db.get("auditLogs").stream().filter(l -> caseId.equals(l.get("caseId"))).toList();
        VerificationResult verification = IntegrityEngine.runFullVerification(caseId);

        String reportId = "RPT-" + System.currentTimeMillis();
        String timestamp = Instant.now().toString();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalEvidenceItems", evidence.size());
        summary.put("totalRecoveredFiles", recoveredFiles.size());
        summary.put("totalAuditEvents", auditLogs.size());
        summary.put("overallIntegrityStatus", verification.getOverallStatus());

        List<Map<String, Object>> evdList = new ArrayList<>();
        for (Map<String, Object> e : evidence) {
            evdList.add(Database.createMap(
                    "id", e.get("id"),
                    "name", e.get("sourceName"),
                    "hash", e.get("originalHash"),
                    "status", e.get("integrityStatus")
            ));
        }

        List<Map<String, Object>> recList = new ArrayList<>();
        for (Map<String, Object> r : recoveredFiles) {
            recList.add(Database.createMap(
                    "name", r.get("filename"),
                    "type", r.get("fileType"),
                    "offset", r.get("offsetHex"),
                    "confidence", r.get("confidenceScore") + "% (" + r.get("confidenceLevel") + ")"
            ));
        }

        List<Map<String, Object>> auditList = new ArrayList<>();
        int start = Math.max(0, auditLogs.size() - 5);
        for (int i = start; i < auditLogs.size(); i++) {
            Map<String, Object> l = auditLogs.get(i);
            String hash = String.valueOf(l.get("hash"));
            auditList.add(Database.createMap(
                    "id", l.get("id"),
                    "time", l.get("timestamp"),
                    "action", l.get("action"),
                    "user", l.get("user"),
                    "hash", hash.length() > 16 ? hash.substring(0, 16) + "..." : hash
            ));
        }

        Map<String, Object> reportData = new LinkedHashMap<>();
        reportData.put("reportId", reportId);
        reportData.put("caseId", c.get("id"));
        reportData.put("caseName", c.get("name"));
        reportData.put("investigator", c.get("investigator"));
        reportData.put("organization", c.get("organization"));
        reportData.put("reportType", reportType);
        reportData.put("generatedAt", timestamp);
        reportData.put("summary", summary);
        reportData.put("evidenceList", evdList);
        reportData.put("recoveredFiles", recList);
        reportData.put("auditTrailSummary", auditList);
        reportData.put("verificationResults", verification.toMap());

        Report report = new Report(
                reportId,
                caseId,
                reportType + " - Case " + caseId,
                reportType,
                format,
                timestamp,
                reportData
        );

        db.insert("reports", report.toMap());

        return reportData;
    }

    /**
     * Builds a standard valid PDF 1.4 binary buffer.
     */
    public static byte[] buildReportPdf(Map<String, Object> reportData) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            StringBuilder textContent = new StringBuilder();

            textContent.append("DataShield Forensics - Digital Forensics & Sanitization Report\\n\\n");
            textContent.append("Report ID: ").append(reportData.get("reportId")).append("\\n");
            textContent.append("Case: ").append(reportData.get("caseId")).append(" - ").append(reportData.get("caseName")).append("\\n");
            textContent.append("Investigator: ").append(reportData.get("investigator")).append("\\n");
            textContent.append("Organization: ").append(reportData.get("organization")).append("\\n");
            textContent.append("Report Type: ").append(reportData.get("reportType")).append("\\n");
            textContent.append("Generated Date: ").append(reportData.get("generatedAt")).append("\\n\\n");

            textContent.append("--- VERIFICATION SUMMARY ---\\n");
            if (reportData.get("verificationResults") instanceof Map<?, ?> v) {
                textContent.append("Evidence Integrity: ").append(v.get("evidenceIntegrity")).append("\\n");
                textContent.append("Recovery Validation: ").append(v.get("recoveryValidation")).append("\\n");
                textContent.append("Audit Chain Integrity: ").append(v.get("auditIntegrity")).append("\\n");
                textContent.append("Overall Case Verification: ").append(v.get("overallStatus")).append("\\n\\n");
            }

            textContent.append("--- RECOVERED EVIDENCE FILES ---\\n");
            if (reportData.get("recoveredFiles") instanceof List<?> rList) {
                int idx = 1;
                for (Object item : rList) {
                    if (item instanceof Map<?, ?> m) {
                        textContent.append(idx++).append(". ").append(m.get("name"))
                                .append(" | ").append(m.get("type"))
                                .append(" | Offset: ").append(m.get("offset"))
                                .append(" | Confidence: ").append(m.get("confidence")).append("\\n");
                    }
                }
            }

            // Build minimal standard PDF-1.4 file
            String body = textContent.toString();
            String[] lines = body.split("\\\\n");

            StringBuilder streamContent = new StringBuilder();
            streamContent.append("BT\n/F1 10 Tf\n50 750 Td\n14 TL\n");
            for (String line : lines) {
                String safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)");
                streamContent.append("(").append(safe).append(") '\n");
            }
            streamContent.append("ET\n");

            byte[] streamBytes = streamContent.toString().getBytes(StandardCharsets.US_ASCII);

            List<Long> offsets = new ArrayList<>();
            out.write("%PDF-1.4\n".getBytes(StandardCharsets.US_ASCII));

            // Obj 1: Catalog
            offsets.add((long) out.size());
            out.write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

            // Obj 2: Pages
            offsets.add((long) out.size());
            out.write("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

            // Obj 3: Page
            offsets.add((long) out.size());
            out.write("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

            // Obj 4: Font
            offsets.add((long) out.size());
            out.write("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".getBytes(StandardCharsets.US_ASCII));

            // Obj 5: Stream
            offsets.add((long) out.size());
            out.write(("5 0 obj\n<< /Length " + streamBytes.length + " >>\nstream\n").getBytes(StandardCharsets.US_ASCII));
            out.write(streamBytes);
            out.write("\nendstream\nendobj\n".getBytes(StandardCharsets.US_ASCII));

            // XRef table
            long xrefOffset = out.size();
            out.write(("xref\n0 6\n0000000000 65535 f \n").getBytes(StandardCharsets.US_ASCII));
            for (Long off : offsets) {
                out.write(String.format("%010d 00000 n \n", off).getBytes(StandardCharsets.US_ASCII));
            }

            // Trailer
            out.write(("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + xrefOffset + "\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));

            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to render PDF: " + e.getMessage(), e);
        }
    }
}

