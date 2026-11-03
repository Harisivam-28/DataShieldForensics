package org.datashield.audit;

import org.datashield.database.Database;
import org.datashield.model.AuditEvent;
import org.datashield.util.HashUtil;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Cryptographic audit engine ensuring tamper-evident chain of custody.
 */
public class AuditEngine {

    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public static AuditEvent addAuditEvent(String caseId, String evidenceId, String user, String action, String result, String details) {
        Database db = Database.getInstance();
        List<Map<String, Object>> logs = db.get("auditLogs");

        String prevHash = GENESIS_HASH;
        if (!logs.isEmpty()) {
            Map<String, Object> last = logs.get(logs.size() - 1);
            if (last.containsKey("hash") && last.get("hash") != null) {
                prevHash = String.valueOf(last.get("hash"));
            }
        }

        String id = String.format("LOG-%03d", logs.size() + 1);
        String timestamp = Instant.now().toString();
        if (evidenceId == null || evidenceId.isBlank()) evidenceId = "N/A";
        if (user == null || user.isBlank()) user = "Investigator";
        if (result == null || result.isBlank()) result = "SUCCESS";

        String rawContent = id + "|" + timestamp + "|" + user + "|" + caseId + "|" + action + "|" + details + "|" + prevHash;
        String hash = HashUtil.sha256(rawContent);

        AuditEvent event = new AuditEvent(id, timestamp, user, caseId, evidenceId, action, result, details, prevHash, hash);
        db.insert("auditLogs", event.toMap());
        return event;
    }

    public static Map<String, Object> verifyAuditChain() {
        Database db = Database.getInstance();
        List<Map<String, Object>> logs = db.get("auditLogs");

        Map<String, Object> res = new LinkedHashMap<>();
        if (logs.isEmpty()) {
            res.put("isValid", true);
            res.put("totalEvents", 0);
            res.put("status", "VERIFIED");
            return res;
        }

        String expectedPrevHash = GENESIS_HASH;

        for (Map<String, Object> log : logs) {
            String id = (String) log.get("id");
            String ts = (String) log.get("timestamp");
            String user = (String) log.get("user");
            String caseId = (String) log.get("caseId");
            String action = (String) log.get("action");
            String details = (String) log.get("details");
            String prevHash = (String) log.get("prevHash");
            String hash = (String) log.get("hash");

            if (!expectedPrevHash.equals(prevHash)) {
                res.put("isValid", false);
                res.put("totalEvents", logs.size());
                res.put("brokenAtStep", id);
                res.put("reason", "Previous hash mismatch at log item " + id + ". Expected " + expectedPrevHash + ", got " + prevHash);
                res.put("status", "TAMPER_DETECTED");
                return res;
            }

            String raw = id + "|" + ts + "|" + user + "|" + caseId + "|" + action + "|" + details + "|" + prevHash;
            String calculatedHash = HashUtil.sha256(raw);

            if (!calculatedHash.equals(hash)) {
                res.put("isValid", false);
                res.put("totalEvents", logs.size());
                res.put("brokenAtStep", id);
                res.put("reason", "Hash tampered at log item " + id + ". Stored: " + hash + ", Calculated: " + calculatedHash);
                res.put("status", "TAMPER_DETECTED");
                return res;
            }

            expectedPrevHash = hash;
        }

        res.put("isValid", true);
        res.put("totalEvents", logs.size());
        res.put("status", "VERIFIED");
        return res;
    }
}

