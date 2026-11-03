package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class AuditEvent {
    private String id;
    private String timestamp;
    private String user;
    private String caseId;
    private String evidenceId;
    private String action;
    private String result;
    private String details;
    private String prevHash;
    private String hash;

    public AuditEvent() {}

    public AuditEvent(String id, String timestamp, String user, String caseId, String evidenceId, String action, String result, String details, String prevHash, String hash) {
        this.id = id;
        this.timestamp = timestamp;
        this.user = user;
        this.caseId = caseId;
        this.evidenceId = evidenceId;
        this.action = action;
        this.result = result;
        this.details = details;
        this.prevHash = prevHash;
        this.hash = hash;
    }

    public static AuditEvent fromMap(Map<String, Object> map) {
        AuditEvent a = new AuditEvent();
        if (map == null) return a;
        a.id = (String) map.get("id");
        a.timestamp = (String) map.get("timestamp");
        a.user = (String) map.get("user");
        a.caseId = (String) map.get("caseId");
        a.evidenceId = (String) map.get("evidenceId");
        a.action = (String) map.get("action");
        a.result = (String) map.get("result");
        a.details = (String) map.get("details");
        a.prevHash = (String) map.get("prevHash");
        a.hash = (String) map.get("hash");
        return a;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("timestamp", timestamp);
        map.put("user", user);
        map.put("caseId", caseId);
        map.put("evidenceId", evidenceId);
        map.put("action", action);
        map.put("result", result);
        map.put("details", details);
        map.put("prevHash", prevHash);
        map.put("hash", hash);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getEvidenceId() { return evidenceId; }
    public void setEvidenceId(String evidenceId) { this.evidenceId = evidenceId; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }

    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }

    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }
}

