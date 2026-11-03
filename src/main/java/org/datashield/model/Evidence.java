package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class Evidence {
    private String id;
    private String caseId;
    private String sourceName;
    private String sourcePath;
    private String type;
    private long sizeBytes;
    private String originalHash;
    private String currentHash;
    private String integrityStatus; // VERIFIED | CHANGED | WARNING
    private String addedTime;
    private boolean readOnly;

    public Evidence() {}

    public Evidence(String id, String caseId, String sourceName, String sourcePath, String type, long sizeBytes, String originalHash, String currentHash, String integrityStatus, String addedTime, boolean readOnly) {
        this.id = id;
        this.caseId = caseId;
        this.sourceName = sourceName;
        this.sourcePath = sourcePath;
        this.type = type;
        this.sizeBytes = sizeBytes;
        this.originalHash = originalHash;
        this.currentHash = currentHash;
        this.integrityStatus = integrityStatus;
        this.addedTime = addedTime;
        this.readOnly = readOnly;
    }

    public static Evidence fromMap(Map<String, Object> map) {
        Evidence e = new Evidence();
        if (map == null) return e;
        e.id = (String) map.get("id");
        e.caseId = (String) map.get("caseId");
        e.sourceName = (String) map.get("sourceName");
        e.sourcePath = (String) map.get("sourcePath");
        e.type = (String) map.get("type");
        Object sz = map.get("sizeBytes");
        e.sizeBytes = sz instanceof Number ? ((Number) sz).longValue() : 0L;
        e.originalHash = (String) map.get("originalHash");
        e.currentHash = (String) map.get("currentHash");
        e.integrityStatus = (String) map.get("integrityStatus");
        e.addedTime = (String) map.get("addedTime");
        e.readOnly = Boolean.TRUE.equals(map.get("readOnly"));
        return e;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("caseId", caseId);
        map.put("sourceName", sourceName);
        map.put("sourcePath", sourcePath);
        map.put("type", type);
        map.put("sizeBytes", sizeBytes);
        map.put("originalHash", originalHash);
        map.put("currentHash", currentHash);
        map.put("integrityStatus", integrityStatus);
        map.put("addedTime", addedTime);
        map.put("readOnly", readOnly);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getSourceName() { return sourceName; }
    public void setSourceName(String sourceName) { this.sourceName = sourceName; }

    public String getSourcePath() { return sourcePath; }
    public void setSourcePath(String sourcePath) { this.sourcePath = sourcePath; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }

    public String getOriginalHash() { return originalHash; }
    public void setOriginalHash(String originalHash) { this.originalHash = originalHash; }

    public String getCurrentHash() { return currentHash; }
    public void setCurrentHash(String currentHash) { this.currentHash = currentHash; }

    public String getIntegrityStatus() { return integrityStatus; }
    public void setIntegrityStatus(String integrityStatus) { this.integrityStatus = integrityStatus; }

    public String getAddedTime() { return addedTime; }
    public void setAddedTime(String addedTime) { this.addedTime = addedTime; }

    public boolean isReadOnly() { return readOnly; }
    public void setReadOnly(boolean readOnly) { this.readOnly = readOnly; }
}

