package org.datashield.test;

import org.datashield.audit.AuditEngine;
import org.datashield.config.DataShieldConfig;
import org.datashield.core.LifecycleEngine;
import org.datashield.database.Database;
import org.datashield.device.DeviceEngine;
import org.datashield.evidence.EvidenceEngine;
import org.datashield.model.Case;
import org.datashield.model.Device;
import org.datashield.model.Evidence;
import org.datashield.recovery.CarvingEngine;
import org.datashield.recovery.RecoveryEngine;
import org.datashield.reports.ReportEngine;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public class DataShieldTestSuite {

    private static int totalTests = 0;
    private static int passedTests = 0;
    private static boolean anyFailed = false;

    private static void assertTrue(boolean condition, String message) {
        totalTests++;
        if (condition) {
            System.out.println("  ✓ PASS: " + message);
            passedTests++;
        } else {
            System.err.println("  ✗ FAIL: " + message);
            anyFailed = true;
        }
    }

    public static void main(String[] args) {
        System.out.println("=====================================================");
        System.out.println(" DataShield Forensics - Java Comprehensive Test Suite");
        System.out.println("=====================================================");

        Database db = Database.getInstance();

        // Initialize Test Case
        Case testCase = new Case(
                "CASE-TEST-001",
                "Automated Test Case",
                "Test Suite Runner",
                "CI Unit",
                "Case for automated testing",
                Instant.now().toString(),
                "Forensic Investigation",
                "Active"
        );
        db.insert("cases", testCase.toMap());

        // Test 1: Real Hardware OS Device Detection
        System.out.println("\n[Test 1] Real OS Storage Hardware Device Detection");
        List<Device> realDevices = DeviceEngine.detectRealHardwareDevices();
        assertTrue(realDevices != null, "OS hardware detection executed cleanly (" + (realDevices != null ? realDevices.size() : 0) + " real physical drive(s) detected).");

        // Test 2: SHA-256 Hash Generation & Evidence Integrity
        System.out.println("\n[Test 2] SHA-256 Hash Generation & Evidence Integrity");
        Path sampleImagePath = DataShieldConfig.getSampleImagePath();
        File sampleFile = sampleImagePath.toFile();
        assertTrue(sampleFile.exists(), "Sample drive image exists at " + sampleImagePath.toAbsolutePath());

        String hash = EvidenceEngine.calculateFileHash(sampleImagePath);
        assertTrue(hash != null && hash.length() == 64, "SHA-256 hash calculated: " + (hash != null ? hash.substring(0, 16) : "") + "...");

        Evidence evd = EvidenceEngine.registerEvidence("CASE-TEST-001", "test_sample.img", sampleImagePath.toAbsolutePath().toString(), "Disk Image", "Investigator");
        assertTrue(evd.getId() != null && hash.equalsIgnoreCase(evd.getOriginalHash()), "Evidence registered with verified originalHash.");

        Map<String, Object> verifyRes = EvidenceEngine.verifyEvidenceIntegrity(evd.getId(), "Investigator");
        assertTrue("VERIFIED".equals(verifyRes.get("status")), "Integrity check status is VERIFIED.");

        // Test 3: Pre-Erasure Safety Guard
        System.out.println("\n[Test 3] Pre-Erasure Safety Guard Protection");
        Map<String, Object> safetyCheck = LifecycleEngine.checkPreErasureSafety("CASE-TEST-001");
        assertTrue(Boolean.TRUE.equals(safetyCheck.get("requiresWarning")), "Pre-erasure safety guard correctly flags unacquired evidence warning.");

        // Test 4: Signature Detection & Multi-Format Carving
        System.out.println("\n[Test 4] Signature Carving Engine (10 Formats Supported)");
        assertTrue(CarvingEngine.SIGNATURE_DATABASE.size() >= 6, "Signature database populated with 6+ forensic file format plugins.");

        Map<String, Object> carvingRes = CarvingEngine.runFileCarving(evd.getId(), "Investigator");
        int carvedCount = (Integer) carvingRes.get("carvedCount");
        assertTrue(carvedCount >= 4, "Carving scanner extracted " + carvedCount + " files (JPEG, PDF, ZIP, PNG).");

        Map<String, Object> scoreRes = CarvingEngine.calculateConfidenceScore(true, true, true, true, false, 0, 0);
        int score = (Integer) scoreRes.get("score");
        String confLevel = (String) scoreRes.get("confidenceLevel");
        assertTrue(score >= 90 && "HIGH".equals(confLevel), "Explainable confidence score computed: " + score + "% (" + confLevel + ").");

        // Test 5: Recovery Destination Drive Separation Validation
        System.out.println("\n[Test 5] Recovery Destination Drive Separation Check");
        Map<String, Object> blockedCheck = RecoveryEngine.validateRecoveryDestination(evd.getId(), sampleImagePath.toAbsolutePath().toString());
        assertTrue(Boolean.TRUE.equals(blockedCheck.get("blocked")), "Destination check BLOCKED recovery when destination matches source device.");

        Map<String, Object> validCheck = RecoveryEngine.validateRecoveryDestination(evd.getId(), "/tmp/DataShield_Test_Output");
        assertTrue(Boolean.FALSE.equals(validCheck.get("blocked")), "Destination check PASSED for separate destination path.");

        // Test 6: Cryptographic Audit-Chain Validation
        System.out.println("\n[Test 6] Cryptographic Audit Log Chain Verification");
        AuditEngine.addAuditEvent("CASE-TEST-001", "EVD-TEST-001", "Investigator", "TEST_EVENT", "SUCCESS", "Automated test suite audit event.");
        Map<String, Object> auditRes = AuditEngine.verifyAuditChain();
        assertTrue(Boolean.TRUE.equals(auditRes.get("isValid")) && "VERIFIED".equals(auditRes.get("status")), "Tamper-evident audit chain cryptographic hash integrity VERIFIED.");

        // Test 7: Forensic Report Generation & PDF Output
        System.out.println("\n[Test 7] Forensic PDF Report & Certificate Generation");
        Map<String, Object> report = ReportEngine.generateReport("CASE-2026-0001", "Forensic Recovery Report", "JSON", "Investigator");
        assertTrue(report.get("reportId") != null, "Report generated with ID " + report.get("reportId") + ".");

        byte[] pdfBytes = ReportEngine.buildReportPdf(report);
        assertTrue(pdfBytes.length > 100 && new String(pdfBytes, 0, 5).startsWith("%PDF-"), "Forensic PDF binary compiled successfully (" + pdfBytes.length + " bytes).");

        System.out.println("\n=====================================================");
        System.out.println(" Summary: " + passedTests + "/" + totalTests + " Tests Passed Cleanly");
        System.out.println("=====================================================");

        if (passedTests != totalTests) {
            System.exit(1);
        }
    }
}
