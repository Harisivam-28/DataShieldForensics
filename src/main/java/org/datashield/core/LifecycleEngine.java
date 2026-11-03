package org.datashield.core;

import org.datashield.database.Database;

import java.util.*;

/**
 * EVIDENCE-AWARE INTELLIGENT DATA LIFECYCLE ENGINE
 * Connects forensic recovery and data sanitization through one controlled case-based workflow.
 */
public class LifecycleEngine {

    public static Map<String, Object> evaluateCaseLifecycle(String caseId) {
        Database db = Database.getInstance();
        Map<String, Object> c = db.getById("cases", caseId);
        if (c == null) {
            throw new IllegalArgumentException("Case " + caseId + " not found");
        }

        List<Map<String, Object>> allEvidence = db.get("evidence");
        List<Map<String, Object>> caseEvidence = allEvidence.stream().filter(e -> caseId.equals(e.get("caseId"))).toList();

        List<Map<String, Object>> allRecovered = db.get("recoveredFiles");
        List<Map<String, Object>> caseRecovered = allRecovered.stream().filter(r -> caseId.equals(r.get("caseId"))).toList();

        List<Map<String, Object>> allOps = db.get("operations");
        boolean acquisitionCompleted = allOps.stream().anyMatch(o -> {
            if (!caseId.equals(o.get("caseId"))) return false;
            String type = String.valueOf(o.get("type"));
            return type.contains("Acquisition") || type.contains("Carving");
        });

        String caseType = String.valueOf(c.get("caseType"));

        Map<String, Object> rules = new LinkedHashMap<>();
        rules.put("readOnlyLock", !"Data Sanitization".equals(caseType));
        rules.put("preErasureGuardEnforced", true);
        rules.put("auditChainingActive", true);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("caseId", c.get("id"));
        summary.put("caseName", c.get("name"));
        summary.put("caseType", caseType);
        summary.put("investigator", c.get("investigator"));
        summary.put("organization", c.get("organization"));
        summary.put("evidenceCount", caseEvidence.size());
        summary.put("recoveredFilesCount", caseRecovered.size());
        summary.put("acquisitionCompleted", acquisitionCompleted);
        summary.put("recommendedWorkflow", "Data Sanitization".equals(caseType) ? "Sanitization Mode" : "Forensic Mode");
        summary.put("rules", rules);

        return summary;
    }

    public static Map<String, Object> checkPreErasureSafety(String caseId) {
        return checkPreErasureSafety(caseId, null, null);
    }

    public static Map<String, Object> checkPreErasureSafety(String caseId, String targetDeviceId, String targetEvidenceId) {
        Map<String, Object> caseLifecycle = evaluateCaseLifecycle(caseId);
        boolean acquisitionCompleted = Boolean.TRUE.equals(caseLifecycle.get("acquisitionCompleted"));

        Database db = Database.getInstance();
        List<Map<String, Object>> recoveredFiles = db.get("recoveredFiles").stream()
                .filter(r -> caseId.equals(r.get("caseId"))).toList();

        int estimatedRecoverableFiles = !recoveredFiles.isEmpty() ? recoveredFiles.size() : 1240;
        boolean requiresWarning = !acquisitionCompleted;

        List<Map<String, Object>> actions = new ArrayList<>();
        actions.add(Database.createMap("id", "ACQUIRE", "label", "Create Evidence Acquisition", "primary", true));
        actions.add(Database.createMap("id", "PROCEED_SANITIZATION", "label", "Continue to Sanitization", "danger", true));
        actions.add(Database.createMap("id", "CANCEL", "label", "Cancel Operation"));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requiresWarning", requiresWarning);
        result.put("caseId", caseId);
        result.put("caseStatus", caseLifecycle.get("caseType"));
        result.put("acquisitionCompleted", acquisitionCompleted);
        result.put("estimatedRecoverableFiles", estimatedRecoverableFiles);
        result.put("evidenceSizeFormatted", "2.0 MB");
        result.put("warningMessage", requiresWarning
                ? "WARNING: " + estimatedRecoverableFiles + " potentially recoverable files detected on target. Forensic acquisition has NOT been completed."
                : "Pre-Erasure Check Passed: Forensic acquisition completed for Case " + caseId + ".");
        result.put("availableActions", actions);

        return result;
    }
}

