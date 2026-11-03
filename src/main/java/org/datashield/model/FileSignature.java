package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class FileSignature {
    private String type;
    private String category;
    private String extension;
    private byte[] headerBytes;
    private byte[] footerBytes;
    private long maxSizeBytes;

    public FileSignature(String type, String category, String extension, byte[] headerBytes, byte[] footerBytes, long maxSizeBytes) {
        this.type = type;
        this.category = category;
        this.extension = extension;
        this.headerBytes = headerBytes;
        this.footerBytes = footerBytes;
        this.maxSizeBytes = maxSizeBytes;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", type);
        map.put("category", category);
        map.put("extension", extension);
        map.put("maxSizeBytes", maxSizeBytes);
        return map;
    }

    public String getType() { return type; }
    public String getCategory() { return category; }
    public String getExtension() { return extension; }
    public byte[] getHeaderBytes() { return headerBytes; }
    public byte[] getFooterBytes() { return footerBytes; }
    public long getMaxSizeBytes() { return maxSizeBytes; }
}

