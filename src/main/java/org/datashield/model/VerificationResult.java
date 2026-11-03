package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class VerificationResult {
    private String caseId;
    private String evidenceIntegrity; // VERIFIED | FAILED
    private String erasureVerification; // VERIFIED | NOT_APPLICABLE
    private String recoveryValidation; // VERIFIED | WARNING
    private String auditIntegrity; // VERIFIED | FAILED
    private String overallStatus; // VERIFIED | WARNING | FAILED
    private String verifiedAt;
    private Object auditChainDetails;
    private Object evidenceDetails;

    public VerificationResult() {}

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("caseId", caseId);
        map.put("evidenceIntegrity", evidenceIntegrity);
        map.put("erasureVerification", erasureVerification);
        map.put("recoveryValidation", recoveryValidation);
        map.put("auditIntegrity", auditIntegrity);
        map.put("overallStatus", overallStatus);
        map.put("verifiedAt", verifiedAt);
        if (auditChainDetails != null) map.put("auditChainDetails", auditChainDetails);
        if (evidenceDetails != null) map.put("evidenceDetails", evidenceDetails);
        return map;
    }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getEvidenceIntegrity() { return evidenceIntegrity; }
    public void setEvidenceIntegrity(String evidenceIntegrity) { this.evidenceIntegrity = evidenceIntegrity; }

    public String getErasureVerification() { return erasureVerification; }
    public void setErasureVerification(String erasureVerification) { this.erasureVerification = erasureVerification; }

    public String getRecoveryValidation() { return recoveryValidation; }
    public void setRecoveryValidation(String recoveryValidation) { this.recoveryValidation = recoveryValidation; }

    public String getAuditIntegrity() { return auditIntegrity; }
    public void setAuditIntegrity(String auditIntegrity) { this.auditIntegrity = auditIntegrity; }

    public String getOverallStatus() { return overallStatus; }
    public void setOverallStatus(String overallStatus) { this.overallStatus = overallStatus; }

    public String getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(String verifiedAt) { this.verifiedAt = verifiedAt; }

    public Object getAuditChainDetails() { return auditChainDetails; }
    public void setAuditChainDetails(Object auditChainDetails) { this.auditChainDetails = auditChainDetails; }

    public Object getEvidenceDetails() { return evidenceDetails; }
    public void setEvidenceDetails(Object evidenceDetails) { this.evidenceDetails = evidenceDetails; }
}

