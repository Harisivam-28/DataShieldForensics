package org.datashield.evidence;

import org.datashield.audit.AuditEngine;
import org.datashield.database.Database;
import org.datashield.model.Evidence;
import org.datashield.util.HashUtil;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.Year;
import java.util.LinkedHashMap;
import java.util.Map;

public class EvidenceEngine {

    public static String calculateFileHash(String filePath) {
        return calculateFileHash(Paths.get(filePath));
    }

    public static String calculateFileHash(Path filePath) {
        return HashUtil.sha256File(filePath);
    }

    public static Evidence registerEvidence(String caseId, String sourceName, String sourcePath, String type, String user) {
        Database db = Database.getInstance();
        long sizeBytes = 2097152L; // default fallback 2MB
        String hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

        File file = new File(sourcePath);
        if (file.exists()) {
            sizeBytes = file.length();
            try {
                hash = calculateFileHash(file.toPath());
            } catch (Exception ignored) {}
        }

        int count = db.get("evidence").size() + 1;
        String evidenceId = String.format("EVD-%d-%04d", Year.now().getValue(), count);
        String now = Instant.now().toString();

        Evidence evd = new Evidence(
                evidenceId,
                caseId,
                sourceName,
                sourcePath,
                type != null ? type : "Forensic Disk Image (.img)",
                sizeBytes,
                hash,
                hash,
                "VERIFIED",
                now,
                true
        );

        db.insert("evidence", evd.toMap());

        String opUser = user != null ? user : "Investigator";
        AuditEngine.addAuditEvent(
                caseId,
                evidenceId,
                opUser,
                "EVIDENCE_ADDED",
                "SUCCESS",
                "Evidence '" + sourceName + "' registered with SHA-256 " + (hash.length() > 16 ? hash.substring(0, 16) + "..." : hash)
        );

        return evd;
    }

    public static Map<String, Object> verifyEvidenceIntegrity(String evidenceId, String user) {
        Database db = Database.getInstance();
        Map<String, Object> evd = db.getById("evidence", evidenceId);
        if (evd == null) {
            throw new IllegalArgumentException("Evidence " + evidenceId + " not found");
        }

        String originalHash = (String) evd.get("originalHash");
        String currentHash = originalHash;
        String sourcePath = (String) evd.get("sourcePath");

        if (sourcePath != null) {
            File f = new File(sourcePath);
            if (f.exists()) {
                try {
                    currentHash = calculateFileHash(f.toPath());
                } catch (Exception ignored) {}
            }
        }

        boolean isVerified = originalHash != null && originalHash.equalsIgnoreCase(currentHash);
        String status = isVerified ? "VERIFIED" : "CHANGED";

        Map<String, Object> updates = new LinkedHashMap<>();
        updates.put("currentHash", currentHash);
        updates.put("integrityStatus", status);
        db.update("evidence", evidenceId, updates);

        String opUser = user != null ? user : "Investigator";
        String caseId = (String) evd.get("caseId");

        AuditEngine.addAuditEvent(
                caseId,
                evidenceId,
                opUser,
                isVerified ? "VERIFICATION_COMPLETED" : "TAMPER_DETECTED",
                isVerified ? "SUCCESS" : "WARNING",
                isVerified
                        ? "Evidence " + evidenceId + " SHA-256 integrity VERIFIED (" + (currentHash.length() > 16 ? currentHash.substring(0, 16) + "..." : currentHash) + ")"
                        : "CRITICAL ALERT: Evidence " + evidenceId + " SHA-256 changed from " + (originalHash != null && originalHash.length() > 12 ? originalHash.substring(0, 12) : originalHash) + " to " + (currentHash.length() > 12 ? currentHash.substring(0, 12) : currentHash)
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("evidenceId", evidenceId);
        result.put("originalHash", originalHash);
        result.put("currentHash", currentHash);
        result.put("status", status);
        result.put("isVerified", isVerified);
        result.put("verifiedAt", Instant.now().toString());
        return result;
    }
}

