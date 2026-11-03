package org.datashield.recovery;

import org.datashield.audit.AuditEngine;
import org.datashield.config.DataShieldConfig;
import org.datashield.database.Database;
import org.datashield.util.HashUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class RecoveryEngine {

    public static Map<String, Object> validateRecoveryDestination(String sourceDeviceId, String destinationPath) {
        if (destinationPath == null || destinationPath.isBlank()) {
            throw new IllegalArgumentException("Recovery destination path is required.");
        }

        Database db = Database.getInstance();
        Map<String, Object> sourceDevice = db.getById("devices", sourceDeviceId);
        Map<String, Object> sourceEvidence = null;

        for (Map<String, Object> e : db.get("evidence")) {
            if (sourceDeviceId.equals(e.get("id")) || sourceDeviceId.equals(e.get("caseId"))) {
                sourceEvidence = e;
                break;
            }
        }

        Path normDest = Paths.get(destinationPath).toAbsolutePath().normalize();
        String normSource = "";

        if (sourceEvidence != null && sourceEvidence.get("sourcePath") != null) {
            normSource = Paths.get(String.valueOf(sourceEvidence.get("sourcePath"))).toAbsolutePath().normalize().toString();
        }

        Map<String, Object> res = new LinkedHashMap<>();

        if (!normSource.isEmpty() && (normDest.toString().equals(normSource) || normDest.toString().startsWith(normSource))) {
            res.put("isValid", false);
            res.put("blocked", true);
            res.put("errorMessage", "Recovery destination must be different from the source evidence device.");
            return res;
        }

        if (sourceDevice != null && sourceDevice.get("devicePath") != null) {
            String devPath = String.valueOf(sourceDevice.get("devicePath"));
            if (normDest.toString().contains(devPath)) {
                res.put("isValid", false);
                res.put("blocked", true);
                res.put("errorMessage", "Recovery destination must be different from the source evidence device.");
                return res;
            }
        }

        res.put("isValid", true);
        res.put("blocked", false);
        res.put("destinationPath", normDest.toString());
        return res;
    }

    public static Map<String, Object> recoverSelectedFile(String fileId, String destinationPath, String caseId, String user) {
        Database db = Database.getInstance();
        Map<String, Object> file = db.getById("recoveredFiles", fileId);
        if (file == null) {
            throw new IllegalArgumentException("Recovered file " + fileId + " not found.");
        }

        String sourceId = file.get("evidenceId") != null ? (String) file.get("evidenceId") : caseId;
        Map<String, Object> check = validateRecoveryDestination(sourceId, destinationPath);
        if (Boolean.TRUE.equals(check.get("blocked"))) {
            throw new IllegalStateException(String.valueOf(check.get("errorMessage")));
        }

        Path destDir = Paths.get(destinationPath).toAbsolutePath();
        try {
            if (!Files.exists(destDir)) {
                Files.createDirectories(destDir);
            }

            String filename = String.valueOf(file.get("filename"));
            Path targetFile = destDir.resolve(filename);

            byte[] recoveredBytes = ("DATASHIELD RECOVERED FILE: " + filename + "\nCase: " + caseId + "\nCategory: " + file.get("category") + "\n").getBytes(StandardCharsets.UTF_8);

            Path sampleDrivePath = DataShieldConfig.getSampleImagePath();
            if (Files.exists(sampleDrivePath) && file.get("offsetDec") != null && file.get("sizeBytes") != null) {
                long offset = ((Number) file.get("offsetDec")).longValue();
                int size = ((Number) file.get("sizeBytes")).intValue();
                byte[] fullDrive = Files.readAllBytes(sampleDrivePath);
                if (offset + size <= fullDrive.length) {
                    recoveredBytes = Arrays.copyOfRange(fullDrive, (int) offset, (int) offset + size);
                }
            }

            Files.write(targetFile, recoveredBytes);
            String sha256 = HashUtil.sha256(recoveredBytes);

            String opUser = user != null ? user : "Investigator";
            AuditEngine.addAuditEvent(
                    caseId,
                    (String) file.get("evidenceId"),
                    opUser,
                    "FILE_RECOVERED_TO_DESTINATION",
                    "SUCCESS",
                    "Recovered " + filename + " to destination " + targetFile + ". SHA-256: " + (sha256.length() > 16 ? sha256.substring(0, 16) + "..." : sha256)
            );

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("fileId", fileId);
            response.put("filename", filename);
            response.put("destinationPath", targetFile.toString());
            response.put("sha256", sha256);
            response.put("sizeBytes", recoveredBytes.length);
            response.put("status", "SUCCESS");
            return response;
        } catch (Exception e) {
            throw new RuntimeException("Failed to recover file: " + e.getMessage(), e);
        }
    }
}
