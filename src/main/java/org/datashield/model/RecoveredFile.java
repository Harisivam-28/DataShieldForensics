package org.datashield.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RecoveredFile {
    private String id;
    private String caseId;
    private String evidenceId;
    private String filename;
    private String fileType;
    private String category;
    private String offsetHex;
    private long offsetDec;
    private long sizeBytes;
    private int confidenceScore;
    private String confidenceLevel; // HIGH | MEDIUM | LOW
    private String reconstructionStatus;
    private List<String> reconstructionReasons = new ArrayList<>();
    private String recoveredAt;
    private int fragmentCount;
    private int missingFragments;

    public RecoveredFile() {}

    @SuppressWarnings("unchecked")
    public static RecoveredFile fromMap(Map<String, Object> map) {
        RecoveredFile r = new RecoveredFile();
        if (map == null) return r;
        r.id = (String) map.get("id");
        r.caseId = (String) map.get("caseId");
        r.evidenceId = (String) map.get("evidenceId");
        r.filename = (String) map.get("filename");
        r.fileType = (String) map.get("fileType");
        r.category = (String) map.get("category");
        r.offsetHex = (String) map.get("offsetHex");
        Object od = map.get("offsetDec");
        r.offsetDec = od instanceof Number ? ((Number) od).longValue() : 0L;
        Object sz = map.get("sizeBytes");
        r.sizeBytes = sz instanceof Number ? ((Number) sz).longValue() : 0L;
        Object cs = map.get("confidenceScore");
        r.confidenceScore = cs instanceof Number ? ((Number) cs).intValue() : 0;
        r.confidenceLevel = (String) map.get("confidenceLevel");
        r.reconstructionStatus = (String) map.get("reconstructionStatus");
        Object reasons = map.get("reconstructionReasons");
        if (reasons instanceof List<?>) {
            for (Object obj : (List<?>) reasons) {
                if (obj != null) r.reconstructionReasons.add(obj.toString());
            }
        }
        r.recoveredAt = (String) map.get("recoveredAt");
        Object fc = map.get("fragmentCount");
        r.fragmentCount = fc instanceof Number ? ((Number) fc).intValue() : 0;
        Object mf = map.get("missingFragments");
        r.missingFragments = mf instanceof Number ? ((Number) mf).intValue() : 0;
        return r;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("caseId", caseId);
        map.put("evidenceId", evidenceId);
        map.put("filename", filename);
        map.put("fileType", fileType);
        map.put("category", category);
        map.put("offsetHex", offsetHex);
        map.put("offsetDec", offsetDec);
        map.put("sizeBytes", sizeBytes);
        map.put("confidenceScore", confidenceScore);
        map.put("confidenceLevel", confidenceLevel);
        map.put("reconstructionStatus", reconstructionStatus);
        map.put("reconstructionReasons", reconstructionReasons);
        map.put("recoveredAt", recoveredAt);
        if (fragmentCount > 0) map.put("fragmentCount", fragmentCount);
        if (missingFragments > 0) map.put("missingFragments", missingFragments);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getEvidenceId() { return evidenceId; }
    public void setEvidenceId(String evidenceId) { this.evidenceId = evidenceId; }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public String getFileType() { return fileType; }
    public void setFileType(String fileType) { this.fileType = fileType; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getOffsetHex() { return offsetHex; }
    public void setOffsetHex(String offsetHex) { this.offsetHex = offsetHex; }

    public long getOffsetDec() { return offsetDec; }
    public void setOffsetDec(long offsetDec) { this.offsetDec = offsetDec; }

    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }

    public int getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(int confidenceScore) { this.confidenceScore = confidenceScore; }

    public String getConfidenceLevel() { return confidenceLevel; }
    public void setConfidenceLevel(String confidenceLevel) { this.confidenceLevel = confidenceLevel; }

    public String getReconstructionStatus() { return reconstructionStatus; }
    public void setReconstructionStatus(String reconstructionStatus) { this.reconstructionStatus = reconstructionStatus; }

    public List<String> getReconstructionReasons() { return reconstructionReasons; }
    public void setReconstructionReasons(List<String> reconstructionReasons) { this.reconstructionReasons = reconstructionReasons; }

    public String getRecoveredAt() { return recoveredAt; }
    public void setRecoveredAt(String recoveredAt) { this.recoveredAt = recoveredAt; }

    public int getFragmentCount() { return fragmentCount; }
    public void setFragmentCount(int fragmentCount) { this.fragmentCount = fragmentCount; }

    public int getMissingFragments() { return missingFragments; }
    public void setMissingFragments(int missingFragments) { this.missingFragments = missingFragments; }
}

