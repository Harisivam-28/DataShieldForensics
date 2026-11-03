package org.datashield.database;

import org.datashield.config.DataShieldConfig;
import org.datashield.util.HashUtil;
import org.datashield.util.JsonUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Thread-safe embedded database with JSON persistence.
 * Initializes the default forensic case dataset with cryptographic integrity.
 */
public class Database {

    private static final Database INSTANCE = new Database();
    public static Database getInstance() { return INSTANCE; }

    private final Map<String, List<Map<String, Object>>> tables = new LinkedHashMap<>();
    private final Path dbFile;

    public Database() {
        this.dbFile = DataShieldConfig.getDbFilePath();
        init();
    }

    private synchronized void init() {
        if (Files.exists(dbFile)) {
            try {
                String json = Files.readString(dbFile, StandardCharsets.UTF_8);
                Map<String, Object> loaded = JsonUtil.parseMap(json);
                for (Map.Entry<String, Object> entry : loaded.entrySet()) {
                    if (entry.getValue() instanceof List<?> list) {
                        List<Map<String, Object>> rows = new ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof Map<?, ?> m) {
                                rows.add(new LinkedHashMap<>((Map<String, Object>) m));
                            }
                        }
                        tables.put(entry.getKey(), rows);
                    }
                }
                if (!tables.containsKey("auditLogs") || tables.get("auditLogs").isEmpty()) {
                    initDefaultAuditLogs();
                    save();
                }
                return;
            } catch (Exception e) {
                System.err.println("[!] Warning: Error reading existing DB JSON, resetting defaults: " + e.getMessage());
            }
        }

        populateDefaults();
        initDefaultAuditLogs();
        save();
    }

    private void populateDefaults() {
        tables.clear();

        // 1. Users
        List<Map<String, Object>> users = new ArrayList<>();
        users.add(createMap("id", "usr_1", "username", "admin", "name", "Dr. Rajesh Verma", "role", "Administrator", "email", "admin@datashield.gov.in", "passwordHash", "sha256_mock_hash"));
        users.add(createMap("id", "usr_2", "username", "investigator", "name", "Sgt. Vikram Singh", "role", "Investigator", "email", "v.singh@cyberforensics.gov.in", "passwordHash", "sha256_mock_hash"));
        users.add(createMap("id", "usr_3", "username", "viewer", "name", "Ananya Sharma", "role", "Viewer", "email", "a.sharma@cybercell.in", "passwordHash", "sha256_mock_hash"));
        tables.put("users", users);

        // 2. Cases
        List<Map<String, Object>> cases = new ArrayList<>();
        cases.add(createMap(
                "id", "CASE-2026-0001",
                "name", "Cyber Heist Disk Forensic Investigation",
                "investigator", "Sgt. Vikram Singh",
                "organization", "Central Digital Forensics Lab (CDFL)",
                "description", "Acquisition and analysis of suspect media image sample_drive.img for financial breach evidence.",
                "createdDate", "2026-09-24T09:30:00.000Z",
                "caseType", "Forensic Investigation",
                "status", "Active"
        ));
        cases.add(createMap(
                "id", "CASE-2026-0002",
                "name", "Departmental Storage Decommissioning",
                "investigator", "Dr. Rajesh Verma",
                "organization", "Defense Cyber Agency",
                "description", "NIST 800-88 Rev 1 compliant secure sanitization of decommissioned NVMe storage arrays.",
                "createdDate", "2026-09-24T11:15:00.000Z",
                "caseType", "Data Sanitization",
                "status", "Active"
        ));
        tables.put("cases", cases);

        // 3. Evidence
        List<Map<String, Object>> evidence = new ArrayList<>();
        String sampleDrivePath = DataShieldConfig.getSampleImagePath().toAbsolutePath().toString();
        String initialHash = "8de9c0f89d96f06248e88b7cb7d96099aaddacfba16fab5f2d282b69f8c7a57c";
        long imgSize = 2097152L;
        File imgFile = new File(sampleDrivePath);
        if (imgFile.exists()) {
            imgSize = imgFile.length();
            try {
                initialHash = HashUtil.sha256File(imgFile.toPath());
            } catch (Exception ignored) {}
        }

        evidence.add(createMap(
                "id", "EVD-2026-0001",
                "caseId", "CASE-2026-0001",
                "sourceName", "sample_drive.img",
                "sourcePath", sampleDrivePath,
                "type", "Forensic Disk Image (.img)",
                "sizeBytes", imgSize,
                "originalHash", initialHash,
                "currentHash", initialHash,
                "integrityStatus", "VERIFIED",
                "addedTime", "2026-09-24T09:32:00.000Z",
                "readOnly", true
        ));
        tables.put("evidence", evidence);

        // 4. Devices
        List<Map<String, Object>> devices = new ArrayList<>();
        devices.add(createMap(
                "id", "DEV-001",
                "name", "Seagate Barracuda ST1000LM048",
                "type", "HDD",
                "capacity", "1.0 TB",
                "capacityBytes", 1000204886016L,
                "filesystem", "NTFS",
                "partitionInfo", "GPT - 2 Partitions (Primary Data, Recovery)",
                "sectorSize", "512 bytes",
                "mountStatus", "Mounted (Read-Only)",
                "readOnlyStatus", true,
                "recommendedWorkflow", "Multi-pass DoD 5220.22-M Overwrite (3 Passes)"
        ));
        devices.add(createMap(
                "id", "DEV-002",
                "name", "Samsung 980 PRO PCIe 4.0 NVMe",
                "type", "NVMe SSD",
                "capacity", "500 GB",
                "capacityBytes", 500107862016L,
                "filesystem", "EXT4",
                "partitionInfo", "GPT - 1 Partition",
                "sectorSize", "4096 bytes",
                "mountStatus", "Unmounted",
                "readOnlyStatus", false,
                "recommendedWorkflow", "NVMe Cryptographic Sanitize / Block Erase + TRIM Verification"
        ));
        devices.add(createMap(
                "id", "DEV-003",
                "name", "SanDisk Ultra USB 3.0",
                "type", "USB Flash",
                "capacity", "32 GB",
                "capacityBytes", 32000000000L,
                "filesystem", "FAT32",
                "partitionInfo", "MBR - 1 Partition",
                "sectorSize", "512 bytes",
                "mountStatus", "Mounted",
                "readOnlyStatus", false,
                "recommendedWorkflow", "Zero-Fill Overwrite + Random Pattern Pass"
        ));
        tables.put("devices", devices);

        // 5. Operations
        List<Map<String, Object>> operations = new ArrayList<>();
        operations.add(createMap(
                "id", "OP-1001",
                "caseId", "CASE-2026-0001",
                "evidenceId", "EVD-2026-0001",
                "type", "Forensic Acquisition & Carving",
                "status", "Completed",
                "timestamp", "2026-09-24T09:35:00.000Z",
                "user", "Sgt. Vikram Singh",
                "details", "Extracted 4 carved files with signature matching."
        ));
        tables.put("operations", operations);

        // 6. Recovered Files
        List<Map<String, Object>> recFiles = new ArrayList<>();
        recFiles.add(createMap(
                "id", "REC-001",
                "caseId", "CASE-2026-0001",
                "evidenceId", "EVD-2026-0001",
                "filename", "carved_evidence_photo_01.jpg",
                "fileType", "JPEG Image",
                "category", "Images",
                "offsetHex", "0x00001000",
                "offsetDec", 4096L,
                "sizeBytes", 138L,
                "confidenceScore", 96,
                "confidenceLevel", "HIGH",
                "reconstructionStatus", "Complete",
                "reconstructionReasons", Arrays.asList(
                        "✓ Valid JPEG magic header (FF D8 FF E0)",
                        "✓ Valid JPEG footer (FF D9)",
                        "✓ Clean header-to-footer length boundary",
                        "✓ Entropy continuity verified"
                ),
                "recoveredAt", "2026-09-24T09:38:00.000Z"
        ));
        recFiles.add(createMap(
                "id", "REC-002",
                "caseId", "CASE-2026-0001",
                "evidenceId", "EVD-2026-0001",
                "filename", "SIH_Forensic_Investigation_Report.pdf",
                "fileType", "PDF Document",
                "category", "Documents",
                "offsetHex", "0x00008000",
                "offsetDec", 32768L,
                "sizeBytes", 218L,
                "confidenceScore", 94,
                "confidenceLevel", "HIGH",
                "reconstructionStatus", "Complete",
                "reconstructionReasons", Arrays.asList(
                        "✓ Valid PDF magic header (%PDF-1.7)",
                        "✓ Valid PDF %%EOF trailer tag detected",
                        "✓ Cross-reference table structure validated",
                        "✓ No stream corruption detected"
                ),
                "recoveredAt", "2026-09-24T09:39:00.000Z"
        ));
        recFiles.add(createMap(
                "id", "REC-003",
                "caseId", "CASE-2026-0001",
                "evidenceId", "EVD-2026-0001",
                "filename", "suspect_evidence_logs.zip",
                "fileType", "ZIP Archive",
                "category", "Archives",
                "offsetHex", "0x00018000",
                "offsetDec", 98304L,
                "sizeBytes", 98L,
                "confidenceScore", 91,
                "confidenceLevel", "HIGH",
                "reconstructionStatus", "Complete",
                "reconstructionReasons", Arrays.asList(
                        "✓ Valid ZIP Local File Header (50 4B 03 04)",
                        "✓ Valid End of Central Directory signature (50 4B 05 06)",
                        "✓ Central directory index verified"
                ),
                "recoveredAt", "2026-09-24T09:40:00.000Z"
        ));
        recFiles.add(createMap(
                "id", "REC-004",
                "caseId", "CASE-2026-0001",
                "evidenceId", "EVD-2026-0001",
                "filename", "intercepted_evidence_diagram.png",
                "fileType", "PNG Image",
                "category", "Images",
                "offsetHex", "0x00030000",
                "offsetDec", 196608L,
                "sizeBytes", 215L,
                "confidenceScore", 87,
                "confidenceLevel", "HIGH",
                "reconstructionStatus", "Reconstructed (3 Fragments)",
                "fragmentCount", 3,
                "missingFragments", 0,
                "reconstructionReasons", Arrays.asList(
                        "✓ Valid PNG header chunk (89 50 4E 47)",
                        "✓ Fragment 1 & 2 continuity sequence validated",
                        "✓ Valid IEND footer chunk detected",
                        "✓ Fragment reconstruction 100% complete"
                ),
                "recoveredAt", "2026-09-24T09:42:00.000Z"
        ));
        tables.put("recoveredFiles", recFiles);

        // 7. Verification results
        List<Map<String, Object>> verifs = new ArrayList<>();
        verifs.add(createMap(
                "id", "VRF-001",
                "caseId", "CASE-2026-0001",
                "evidenceIntegrity", "VERIFIED",
                "erasureVerification", "NOT_APPLICABLE",
                "recoveryValidation", "VERIFIED",
                "auditIntegrity", "VERIFIED",
                "overallStatus", "VERIFIED",
                "lastVerified", "2026-09-24T09:45:00.000Z"
        ));
        tables.put("verificationResults", verifs);

        // 8. Empty reports
        tables.put("reports", new ArrayList<>());
    }

    private void initDefaultAuditLogs() {
        String genesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
        String prevHash = genesisHash;

        List<Map<String, Object>> initialEvents = new ArrayList<>();
        initialEvents.add(createMap("id", "LOG-001", "timestamp", "2026-09-24T09:30:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "N/A", "action", "CASE_CREATED", "result", "SUCCESS", "details", "Case CASE-2026-0001 initialized by Sgt. Vikram Singh."));
        initialEvents.add(createMap("id", "LOG-002", "timestamp", "2026-09-24T09:32:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "EVIDENCE_ADDED", "result", "SUCCESS", "details", "Evidence sample_drive.img registered with READ-ONLY lock."));
        initialEvents.add(createMap("id", "LOG-003", "timestamp", "2026-09-24T09:33:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "HASH_CREATED", "result", "SUCCESS", "details", "SHA-256 computed: 8de9c0f89d96f062... VERIFIED."));
        initialEvents.add(createMap("id", "LOG-004", "timestamp", "2026-09-24T09:35:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "DEVICE_ANALYZED", "result", "SUCCESS", "details", "Device structure analyzed: raw image, 2MB capacity."));
        initialEvents.add(createMap("id", "LOG-005", "timestamp", "2026-09-24T09:37:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "RECOVERY_STARTED", "result", "SUCCESS", "details", "Signature carving initiated with 6 active signature plugins."));
        initialEvents.add(createMap("id", "LOG-006", "timestamp", "2026-09-24T09:42:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "FILE_RECOVERED", "result", "SUCCESS", "details", "4 evidence files recovered (JPG, PDF, ZIP, PNG) with avg confidence 92%."));
        initialEvents.add(createMap("id", "LOG-007", "timestamp", "2026-09-24T09:45:00.000Z", "user", "Sgt. Vikram Singh", "caseId", "CASE-2026-0001", "evidenceId", "EVD-2026-0001", "action", "VERIFICATION_COMPLETED", "result", "SUCCESS", "details", "Cryptographic hash and recovery structure verification passed."));

        List<Map<String, Object>> auditLogs = new ArrayList<>();
        for (Map<String, Object> evt : initialEvents) {
            String id = (String) evt.get("id");
            String ts = (String) evt.get("timestamp");
            String user = (String) evt.get("user");
            String caseId = (String) evt.get("caseId");
            String action = (String) evt.get("action");
            String details = (String) evt.get("details");

            String raw = id + "|" + ts + "|" + user + "|" + caseId + "|" + action + "|" + details + "|" + prevHash;
            String hash = HashUtil.sha256(raw);

            Map<String, Object> logItem = new LinkedHashMap<>(evt);
            logItem.put("prevHash", prevHash);
            logItem.put("hash", hash);

            prevHash = hash;
            auditLogs.add(logItem);
        }
        tables.put("auditLogs", auditLogs);
    }

    public synchronized void save() {
        try {
            if (dbFile.getParent() != null && !Files.exists(dbFile.getParent())) {
                Files.createDirectories(dbFile.getParent());
            }
            String json = JsonUtil.toPrettyJson(tables);
            Files.writeString(dbFile, json, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[!] Failed to save database: " + e.getMessage());
        }
    }

    public synchronized List<Map<String, Object>> get(String collection) {
        List<Map<String, Object>> list = tables.get(collection);
        if (list == null) return Collections.emptyList();
        return new ArrayList<>(list);
    }

    public synchronized Map<String, Object> getById(String collection, String id) {
        List<Map<String, Object>> list = tables.get(collection);
        if (list == null) return null;
        for (Map<String, Object> item : list) {
            if (id != null && id.equals(item.get("id"))) {
                return new LinkedHashMap<>(item);
            }
        }
        return null;
    }

    public synchronized Map<String, Object> insert(String collection, Map<String, Object> item) {
        tables.computeIfAbsent(collection, k -> new ArrayList<>()).add(new LinkedHashMap<>(item));
        save();
        return item;
    }

    public synchronized Map<String, Object> update(String collection, String id, Map<String, Object> updates) {
        List<Map<String, Object>> list = tables.get(collection);
        if (list == null) return null;
        for (int i = 0; i < list.size(); i++) {
            Map<String, Object> item = list.get(i);
            if (id != null && id.equals(item.get("id"))) {
                item.putAll(updates);
                save();
                return new LinkedHashMap<>(item);
            }
        }
        return null;
    }

    public synchronized boolean delete(String collection, String id) {
        List<Map<String, Object>> list = tables.get(collection);
        if (list == null) return false;
        boolean removed = list.removeIf(item -> id != null && id.equals(item.get("id")));
        if (removed) save();
        return removed;
    }

    public static Map<String, Object> createMap(Object... keyValues) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            if (i + 1 < keyValues.length) {
                m.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
            }
        }
        return m;
    }
}

