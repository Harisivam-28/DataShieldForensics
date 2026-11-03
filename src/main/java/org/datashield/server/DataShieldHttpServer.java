package org.datashield.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.datashield.audit.AuditEngine;
import org.datashield.config.DataShieldConfig;
import org.datashield.core.LifecycleEngine;
import org.datashield.database.Database;
import org.datashield.device.DeviceEngine;
import org.datashield.erasure.ErasureEngine;
import org.datashield.evidence.EvidenceEngine;
import org.datashield.integrity.IntegrityEngine;
import org.datashield.model.Case;
import org.datashield.model.Evidence;
import org.datashield.model.SanitizationCertificate;
import org.datashield.recovery.CarvingEngine;
import org.datashield.recovery.FragmentEngine;
import org.datashield.recovery.RecoveryEngine;
import org.datashield.reports.ReportEngine;
import org.datashield.util.JsonUtil;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Year;
import java.util.*;
import java.util.concurrent.Executors;

public class DataShieldHttpServer {

    private final int port;
    private HttpServer server;

    public DataShieldHttpServer(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // Root router handler handles all paths
        server.createContext("/", new ApiRouterHandler());

        server.start();
        System.out.println("[+] DataShield Forensics Java Backend Server running on http://localhost:" + port);
        System.out.println("[+] Real OS Storage Hardware Detection: ENABLED");
        System.out.println("[+] Safe Demo Mode: ENABLED");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static class ApiRouterHandler implements HttpHandler {
        private final Database db = Database.getInstance();
        private final Path frontendDist = DataShieldConfig.getFrontendDistDir();

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // Enable CORS
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");

                String method = exchange.getRequestMethod().toUpperCase();
                if ("OPTIONS".equals(method)) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                URI uri = exchange.getRequestURI();
                String path = uri.getPath();
                Map<String, String> queryParams = parseQueryParams(uri.getQuery());

                // Route API endpoints
                if ("/health".equals(path)) {
                    handleHealth(exchange);
                } else if ("/api/status".equals(path)) {
                    handleStatus(exchange);
                } else if ("/api/cases".equals(path)) {
                    if ("GET".equals(method)) handleGetCases(exchange);
                    else if ("POST".equals(method)) handleCreateCase(exchange);
                    else sendError(exchange, 405, "Method not allowed");
                } else if (path.startsWith("/api/cases/")) {
                    String caseId = path.substring("/api/cases/".length());
                    handleGetCaseById(exchange, caseId);
                } else if ("/api/evidence".equals(path)) {
                    if ("GET".equals(method)) handleGetEvidence(exchange, queryParams.get("caseId"));
                    else if ("POST".equals(method)) handleRegisterEvidence(exchange);
                    else sendError(exchange, 405, "Method not allowed");
                } else if (path.startsWith("/api/evidence/") && path.endsWith("/verify")) {
                    String evdId = path.substring("/api/evidence/".length(), path.length() - "/verify".length());
                    handleVerifyEvidence(exchange, evdId);
                } else if ("/api/devices".equals(path)) {
                    handleGetDevices(exchange);
                } else if ("/api/devices/detect".equals(path)) {
                    handleDetectDevices(exchange);
                } else if (path.startsWith("/api/devices/") && path.endsWith("/analyze")) {
                    String devId = path.substring("/api/devices/".length(), path.length() - "/analyze".length());
                    handleAnalyzeDevice(exchange, devId);
                } else if ("/api/recovery/signatures".equals(path)) {
                    handleGetSignatures(exchange);
                } else if ("/api/recovery/files".equals(path)) {
                    handleGetRecoveredFiles(exchange, queryParams.get("caseId"));
                } else if ("/api/recovery/carve".equals(path)) {
                    handleCarveFiles(exchange);
                } else if ("/api/recovery/validate-destination".equals(path)) {
                    handleValidateDestination(exchange);
                } else if ("/api/recovery/restore".equals(path)) {
                    handleRestoreFile(exchange);
                } else if ("/api/recovery/reconstruct".equals(path)) {
                    handleReconstructFragments(exchange);
                } else if ("/api/erasure/methods".equals(path)) {
                    handleGetErasureMethods(exchange);
                } else if ("/api/erasure/pre-check".equals(path)) {
                    handlePreErasureCheck(exchange, queryParams);
                } else if ("/api/erasure/drive".equals(path)) {
                    handleEraseDrive(exchange);
                } else if ("/api/sandbox/files".equals(path)) {
                    handleGetSandboxFiles(exchange);
                } else if ("/api/erasure/files".equals(path)) {
                    handleEraseFiles(exchange);
                } else if ("/api/verification".equals(path)) {
                    handleVerification(exchange, queryParams.get("caseId"));
                } else if ("/api/audit".equals(path)) {
                    handleGetAuditLogs(exchange, queryParams.get("caseId"));
                } else if ("/api/audit/verify".equals(path)) {
                    handleVerifyAuditChain(exchange);
                } else if ("/api/reports".equals(path)) {
                    handleGetReports(exchange, queryParams.get("caseId"));
                } else if ("/api/reports/generate".equals(path)) {
                    handleGenerateReport(exchange);
                } else if (path.startsWith("/api/reports/") && path.endsWith("/pdf")) {
                    String rptId = path.substring("/api/reports/".length(), path.length() - "/pdf".length());
                    handleDownloadReportPdf(exchange, rptId);
                } else {
                    // Static Frontend Handling
                    serveStaticFileOrSpa(exchange, path);
                }
            } catch (Exception e) {
                e.printStackTrace();
                sendError(exchange, 500, e.getMessage());
            }
        }

        private void handleHealth(HttpExchange exchange) throws IOException {
            Map<String, Object> resp = Database.createMap(
                    "status", "OK",
                    "application", "DataShield Forensics Java Backend",
                    "version", DataShieldConfig.VERSION,
                    "timestamp", Instant.now().toString()
            );
            sendJson(exchange, 200, resp);
        }

        private void handleStatus(HttpExchange exchange) throws IOException {
            Map<String, Object> resp = Database.createMap(
                    "status", "ONLINE",
                    "application", "DataShield Forensics",
                    "version", DataShieldConfig.VERSION,
                    "safeDemoMode", true,
                    "lifecycleEngine", "Evidence-Aware Intelligent Data Lifecycle Engine ACTIVE",
                    "database", "Java Embedded Forensic Store Connected",
                    "totalCases", db.get("cases").size(),
                    "activeEvidence", db.get("evidence").size(),
                    "timestamp", Instant.now().toString()
            );
            sendJson(exchange, 200, resp);
        }

        private void handleGetCases(HttpExchange exchange) throws IOException {
            sendJson(exchange, 200, db.get("cases"));
        }

        private void handleGetCaseById(HttpExchange exchange, String caseId) throws IOException {
            Map<String, Object> c = db.getById("cases", caseId);
            if (c == null) {
                sendError(exchange, 404, "Case not found");
                return;
            }

            List<Map<String, Object>> evd = db.get("evidence").stream().filter(e -> caseId.equals(e.get("caseId"))).toList();
            List<Map<String, Object>> rec = db.get("recoveredFiles").stream().filter(r -> caseId.equals(r.get("caseId"))).toList();
            List<Map<String, Object>> logs = db.get("auditLogs").stream().filter(l -> caseId.equals(l.get("caseId"))).toList();
            Map<String, Object> lifecycle = LifecycleEngine.evaluateCaseLifecycle(caseId);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("case", c);
            result.put("evidence", evd);
            result.put("recoveredFiles", rec);
            result.put("auditLogs", logs);
            result.put("lifecycle", lifecycle);

            sendJson(exchange, 200, result);
        }

        private void handleCreateCase(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String name = (String) body.get("name");
            String caseType = (String) body.get("caseType");
            if (name == null || name.isBlank() || caseType == null || caseType.isBlank()) {
                sendError(exchange, 400, "Case name and caseType are required.");
                return;
            }

            int count = db.get("cases").size() + 1;
            String caseId = String.format("CASE-%d-%04d", Year.now().getValue(), count);
            String investigator = body.get("investigator") != null ? (String) body.get("investigator") : "Investigator S. Sharma";
            String org = body.get("organization") != null ? (String) body.get("organization") : "Central Digital Forensics Lab (CDFL)";
            String desc = body.get("description") != null ? (String) body.get("description") : "Digital evidence investigation and sanitization case.";

            Case c = new Case(caseId, name, investigator, org, desc, Instant.now().toString(), caseType, "Active");
            db.insert("cases", c.toMap());

            AuditEngine.addAuditEvent(caseId, "N/A", investigator, "CASE_CREATED", "SUCCESS", "Case " + caseId + " (" + name + ") created under category " + caseType + ".");
            sendJson(exchange, 201, c.toMap());
        }

        private void handleGetEvidence(HttpExchange exchange, String caseId) throws IOException {
            List<Map<String, Object>> list = db.get("evidence");
            if (caseId != null && !caseId.isBlank()) {
                list = list.stream().filter(e -> caseId.equals(e.get("caseId"))).toList();
            }
            sendJson(exchange, 200, list);
        }

        private void handleRegisterEvidence(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String caseId = (String) body.get("caseId");
            String sourceName = (String) body.get("sourceName");
            if (caseId == null || sourceName == null) {
                sendError(exchange, 400, "caseId and sourceName are required.");
                return;
            }

            String sourcePath = (String) body.get("sourcePath");
            if (sourcePath == null || sourcePath.isBlank()) {
                sourcePath = DataShieldConfig.getSampleImagePath().toAbsolutePath().toString();
            }

            Evidence evd = EvidenceEngine.registerEvidence(caseId, sourceName, sourcePath, (String) body.get("type"), (String) body.get("user"));
            sendJson(exchange, 201, evd.toMap());
        }

        private void handleVerifyEvidence(HttpExchange exchange, String evdId) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String user = body.get("user") != null ? (String) body.get("user") : "Investigator";
            Map<String, Object> res = EvidenceEngine.verifyEvidenceIntegrity(evdId, user);
            sendJson(exchange, 200, res);
        }

        private void handleGetDevices(HttpExchange exchange) throws IOException {
            DeviceEngine.detectRealHardwareDevices();
            sendJson(exchange, 200, db.get("devices"));
        }

        private void handleDetectDevices(HttpExchange exchange) throws IOException {
            var devs = DeviceEngine.detectRealHardwareDevices();
            Map<String, Object> resp = Database.createMap(
                    "realDeviceCount", devs.size(),
                    "devices", db.get("devices")
            );
            sendJson(exchange, 200, resp);
        }

        private void handleAnalyzeDevice(HttpExchange exchange, String devId) throws IOException {
            Map<String, Object> analysis = DeviceEngine.analyzeDevice(devId);
            sendJson(exchange, 200, analysis);
        }

        private void handleGetSignatures(HttpExchange exchange) throws IOException {
            List<Map<String, Object>> list = new ArrayList<>();
            for (var sig : CarvingEngine.SIGNATURE_DATABASE) {
                list.add(sig.toMap());
            }
            sendJson(exchange, 200, list);
        }

        private void handleGetRecoveredFiles(HttpExchange exchange, String caseId) throws IOException {
            List<Map<String, Object>> files = db.get("recoveredFiles");
            if (caseId != null && !caseId.isBlank()) {
                files = files.stream().filter(r -> caseId.equals(r.get("caseId"))).toList();
            }
            sendJson(exchange, 200, files);
        }

        private void handleCarveFiles(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String evidenceId = (String) body.get("evidenceId");
            if (evidenceId == null) {
                sendError(exchange, 400, "evidenceId is required");
                return;
            }
            Map<String, Object> res = CarvingEngine.runFileCarving(evidenceId, (String) body.get("user"));
            sendJson(exchange, 200, res);
        }

        private void handleValidateDestination(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String sourceDeviceId = (String) body.get("sourceDeviceId");
            String destinationPath = (String) body.get("destinationPath");
            Map<String, Object> check = RecoveryEngine.validateRecoveryDestination(sourceDeviceId, destinationPath);
            sendJson(exchange, 200, check);
        }

        private void handleRestoreFile(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String fileId = (String) body.get("fileId");
            String dest = (String) body.get("destinationPath");
            String caseId = (String) body.get("caseId");
            if (fileId == null || dest == null || caseId == null) {
                sendError(exchange, 400, "fileId, destinationPath, and caseId are required.");
                return;
            }
            Map<String, Object> res = RecoveryEngine.recoverSelectedFile(fileId, dest, caseId, (String) body.get("user"));
            sendJson(exchange, 200, res);
        }

        @SuppressWarnings("unchecked")
        private void handleReconstructFragments(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String caseId = (String) body.get("caseId");
            String evidenceId = (String) body.get("evidenceId");
            List<Map<String, Object>> fragmentMap = (List<Map<String, Object>>) body.get("fragmentMap");
            String targetFilename = (String) body.get("targetFilename");
            Map<String, Object> res = FragmentEngine.reconstructFragments(caseId, evidenceId, fragmentMap, targetFilename);
            sendJson(exchange, 200, res);
        }

        private void handleGetErasureMethods(HttpExchange exchange) throws IOException {
            sendJson(exchange, 200, ErasureEngine.SANITIZATION_METHODS);
        }

        private void handlePreErasureCheck(HttpExchange exchange, Map<String, String> query) throws IOException {
            String caseId = query.get("caseId");
            if (caseId == null || caseId.isBlank()) {
                sendError(exchange, 400, "caseId parameter required");
                return;
            }
            Map<String, Object> res = LifecycleEngine.checkPreErasureSafety(caseId, query.get("targetDeviceId"), query.get("targetEvidenceId"));
            sendJson(exchange, 200, res);
        }

        private void handleEraseDrive(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String caseId = (String) body.get("caseId");
            String deviceId = (String) body.get("deviceId");
            String confirmationPhrase = (String) body.get("confirmationPhrase");
            if (caseId == null || deviceId == null || confirmationPhrase == null) {
                sendError(exchange, 400, "caseId, deviceId, and confirmationPhrase are required.");
                return;
            }
            boolean safeDemo = !Boolean.FALSE.equals(body.get("safeDemoMode"));
            SanitizationCertificate cert = ErasureEngine.executeDriveErasure(caseId, deviceId, (String) body.get("methodId"), confirmationPhrase, (String) body.get("user"), safeDemo);
            sendJson(exchange, 200, cert.toMap());
        }

        private void handleGetSandboxFiles(HttpExchange exchange) throws IOException {
            Path sandboxDir = DataShieldConfig.getSandboxDir();
            List<Map<String, Object>> fileList = new ArrayList<>();
            if (Files.exists(sandboxDir)) {
                try (var stream = Files.list(sandboxDir)) {
                    for (Path p : stream.toList()) {
                        if (Files.isRegularFile(p)) {
                            long size = Files.size(p);
                            String hash = EvidenceEngine.calculateFileHash(p);
                            fileList.add(Database.createMap(
                                    "filename", p.getFileName().toString(),
                                    "path", p.toAbsolutePath().toString(),
                                    "sizeBytes", size,
                                    "modifiedDate", Files.getLastModifiedTime(p).toString(),
                                    "hash", hash
                            ));
                        }
                    }
                }
            }
            sendJson(exchange, 200, fileList);
        }

        @SuppressWarnings("unchecked")
        private void handleEraseFiles(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String caseId = (String) body.get("caseId");
            List<String> filePaths = (List<String>) body.get("filePaths");
            if (caseId == null || filePaths == null || filePaths.isEmpty()) {
                sendError(exchange, 400, "caseId and filePaths array required.");
                return;
            }
            var res = ErasureEngine.executeFileErasure(caseId, filePaths, (String) body.get("methodId"), (String) body.get("user"));
            sendJson(exchange, 200, res);
        }

        private void handleVerification(HttpExchange exchange, String caseId) throws IOException {
            var res = IntegrityEngine.runFullVerification(caseId);
            sendJson(exchange, 200, res.toMap());
        }

        private void handleGetAuditLogs(HttpExchange exchange, String caseId) throws IOException {
            List<Map<String, Object>> logs = db.get("auditLogs");
            if (caseId != null && !caseId.isBlank()) {
                logs = logs.stream().filter(l -> caseId.equals(l.get("caseId"))).toList();
            }
            sendJson(exchange, 200, logs);
        }

        private void handleVerifyAuditChain(HttpExchange exchange) throws IOException {
            Map<String, Object> check = AuditEngine.verifyAuditChain();
            sendJson(exchange, 200, check);
        }

        private void handleGetReports(HttpExchange exchange, String caseId) throws IOException {
            List<Map<String, Object>> reports = db.get("reports");
            if (caseId != null && !caseId.isBlank()) {
                reports = reports.stream().filter(r -> caseId.equals(r.get("caseId"))).toList();
            }
            sendJson(exchange, 200, reports);
        }

        private void handleGenerateReport(HttpExchange exchange) throws IOException {
            Map<String, Object> body = parseJsonBody(exchange);
            String caseId = (String) body.get("caseId");
            if (caseId == null || caseId.isBlank()) {
                sendError(exchange, 400, "caseId is required");
                return;
            }
            Map<String, Object> rpt = ReportEngine.generateReport(caseId, (String) body.get("reportType"), (String) body.get("format"), (String) body.get("user"));
            sendJson(exchange, 200, rpt);
        }

        @SuppressWarnings("unchecked")
        private void handleDownloadReportPdf(HttpExchange exchange, String rptId) throws IOException {
            Map<String, Object> rpt = db.getById("reports", rptId);
            if (rpt == null) {
                sendError(exchange, 404, "Report not found");
                return;
            }

            Map<String, Object> reportData = (Map<String, Object>) rpt.get("data");
            if (reportData == null) reportData = rpt;

            byte[] pdfBytes = ReportEngine.buildReportPdf(reportData);

            exchange.getResponseHeaders().set("Content-Type", "application/pdf");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + rptId + "_Report.pdf\"");
            exchange.sendResponseHeaders(200, pdfBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(pdfBytes);
            }
        }

        private void serveStaticFileOrSpa(HttpExchange exchange, String path) throws IOException {
            if (!Files.exists(frontendDist)) {
                sendError(exchange, 404, "Frontend static dist folder not found");
                return;
            }

            String relPath = path.startsWith("/") ? path.substring(1) : path;
            if (relPath.isEmpty()) relPath = "index.html";

            Path target = frontendDist.resolve(relPath).normalize();
            if (!target.startsWith(frontendDist) || !Files.exists(target) || Files.isDirectory(target)) {
                // SPA fallback to index.html
                target = frontendDist.resolve("index.html");
            }

            if (Files.exists(target)) {
                String mime = getMimeType(target.getFileName().toString());
                byte[] fileBytes = Files.readAllBytes(target);
                exchange.getResponseHeaders().set("Content-Type", mime);
                exchange.sendResponseHeaders(200, fileBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(fileBytes);
                }
            } else {
                sendError(exchange, 404, "File not found");
            }
        }

        private String getMimeType(String filename) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".html")) return "text/html; charset=utf-8";
            if (lower.endsWith(".css")) return "text/css; charset=utf-8";
            if (lower.endsWith(".js")) return "application/javascript; charset=utf-8";
            if (lower.endsWith(".svg")) return "image/svg+xml";
            if (lower.endsWith(".png")) return "image/png";
            if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
            if (lower.endsWith(".json")) return "application/json; charset=utf-8";
            if (lower.endsWith(".pdf")) return "application/pdf";
            return "application/octet-stream";
        }

        private Map<String, Object> parseJsonBody(HttpExchange exchange) {
            try (InputStream is = exchange.getRequestBody()) {
                String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                return JsonUtil.parseMap(body);
            } catch (Exception e) {
                return new LinkedHashMap<>();
            }
        }

        private void sendJson(HttpExchange exchange, int statusCode, Object data) throws IOException {
            String json = JsonUtil.toJson(data);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
            Map<String, Object> err = Database.createMap("error", message);
            sendJson(exchange, statusCode, err);
        }

        private Map<String, String> parseQueryParams(String query) {
            Map<String, String> params = new LinkedHashMap<>();
            if (query == null || query.isBlank()) return params;
            for (String pair : query.split("&")) {
                int idx = pair.indexOf("=");
                if (idx > 0) {
                    String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                    String val = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                    params.put(key, val);
                }
            }
            return params;
        }
    }
}

