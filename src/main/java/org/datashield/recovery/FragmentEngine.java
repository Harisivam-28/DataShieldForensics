package org.datashield.recovery;

import org.datashield.database.Database;

import java.time.Instant;
import java.util.*;

public class FragmentEngine {

    public static Map<String, Object> reconstructFragments(String caseId, String evidenceId, List<Map<String, Object>> fragmentMap, String targetFilename) {
        if (targetFilename == null || targetFilename.isBlank()) {
            targetFilename = "reconstructed_evidence.jpg";
        }

        List<Map<String, Object>> fragments = fragmentMap;
        if (fragments == null || fragments.isEmpty()) {
            fragments = new ArrayList<>();
            fragments.add(Database.createMap("id", "FRAG-1", "offsetHex", "0x00030000", "size", "64 KB", "status", "VALIDATED_HEADER", "header", "PNG Magic (89 50 4E 47)"));
            fragments.add(Database.createMap("id", "FRAG-2", "offsetHex", "0x00038000", "size", "128 KB", "status", "VALIDATED_BODY", "header", "IDAT Data Chunk"));
            fragments.add(Database.createMap("id", "FRAG-3", "offsetHex", "0x00040000", "size", "32 KB", "status", "VALIDATED_FOOTER", "header", "IEND Trailer (49 45 4E 44)"));
        }

        int totalFragments = fragments.size();
        long validCount = fragments.stream().filter(f -> String.valueOf(f.get("status")).startsWith("VALIDATED")).count();
        int missingCount = (int) (totalFragments - validCount);

        int confidenceScore = (int) Math.round(((double) validCount / totalFragments) * 92);
        boolean isValidated = missingCount == 0;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("reconstructionId", "RECON-" + System.currentTimeMillis());
        result.put("caseId", caseId);
        result.put("evidenceId", evidenceId);
        result.put("targetFilename", targetFilename);
        result.put("fragmentCount", totalFragments);
        result.put("missingFragments", missingCount);
        result.put("confidenceScore", confidenceScore);
        result.put("confidenceLevel", confidenceScore >= 80 ? "HIGH" : "MEDIUM");
        result.put("validationStatus", isValidated ? "VALIDATED" : "PARTIAL");
        result.put("fragments", fragments);
        result.put("reconstructedAt", Instant.now().toString());

        return result;
    }
}

