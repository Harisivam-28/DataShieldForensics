package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class SanitizationCertificate {
    private String certificateId;
    private String caseId;
    private String deviceId;
    private String deviceName;
    private String deviceCapacity;
    private String deviceFilesystem;
    private String sanitizationMethod;
    private String standardCompliance;
    private int passesCompleted;
    private String preErasureHash;
    private String postErasureHash;
    private String verificationResult;
    private String sanitizedAt;
    private String operator;
    private boolean safeDemoMode;

    public SanitizationCertificate() {}

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("certificateId", certificateId);
        map.put("caseId", caseId);
        map.put("deviceId", deviceId);
        map.put("deviceName", deviceName);
        map.put("deviceCapacity", deviceCapacity);
        map.put("deviceFilesystem", deviceFilesystem);
        map.put("sanitizationMethod", sanitizationMethod);
        map.put("standardCompliance", standardCompliance);
        map.put("passesCompleted", passesCompleted);
        map.put("preErasureHash", preErasureHash);
        map.put("postErasureHash", postErasureHash);
        map.put("verificationResult", verificationResult);
        map.put("sanitizedAt", sanitizedAt);
        map.put("operator", operator);
        map.put("safeDemoMode", safeDemoMode);
        return map;
    }

    public String getCertificateId() { return certificateId; }
    public void setCertificateId(String certificateId) { this.certificateId = certificateId; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getDeviceName() { return deviceName; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }

    public String getDeviceCapacity() { return deviceCapacity; }
    public void setDeviceCapacity(String deviceCapacity) { this.deviceCapacity = deviceCapacity; }

    public String getDeviceFilesystem() { return deviceFilesystem; }
    public void setDeviceFilesystem(String deviceFilesystem) { this.deviceFilesystem = deviceFilesystem; }

    public String getSanitizationMethod() { return sanitizationMethod; }
    public void setSanitizationMethod(String sanitizationMethod) { this.sanitizationMethod = sanitizationMethod; }

    public String getStandardCompliance() { return standardCompliance; }
    public void setStandardCompliance(String standardCompliance) { this.standardCompliance = standardCompliance; }

    public int getPassesCompleted() { return passesCompleted; }
    public void setPassesCompleted(int passesCompleted) { this.passesCompleted = passesCompleted; }

    public String getPreErasureHash() { return preErasureHash; }
    public void setPreErasureHash(String preErasureHash) { this.preErasureHash = preErasureHash; }

    public String getPostErasureHash() { return postErasureHash; }
    public void setPostErasureHash(String postErasureHash) { this.postErasureHash = postErasureHash; }

    public String getVerificationResult() { return verificationResult; }
    public void setVerificationResult(String verificationResult) { this.verificationResult = verificationResult; }

    public String getSanitizedAt() { return sanitizedAt; }
    public void setSanitizedAt(String sanitizedAt) { this.sanitizedAt = sanitizedAt; }

    public String getOperator() { return operator; }
    public void setOperator(String operator) { this.operator = operator; }

    public boolean isSafeDemoMode() { return safeDemoMode; }
    public void setSafeDemoMode(boolean safeDemoMode) { this.safeDemoMode = safeDemoMode; }
}

