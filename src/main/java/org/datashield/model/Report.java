package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class Report {
    private String id;
    private String caseId;
    private String title;
    private String type;
    private String format;
    private String generatedAt;
    private Map<String, Object> data;

    public Report() {}

    public Report(String id, String caseId, String title, String type, String format, String generatedAt, Map<String, Object> data) {
        this.id = id;
        this.caseId = caseId;
        this.title = title;
        this.type = type;
        this.format = format;
        this.generatedAt = generatedAt;
        this.data = data;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("caseId", caseId);
        map.put("title", title);
        map.put("type", type);
        map.put("format", format);
        map.put("generatedAt", generatedAt);
        map.put("data", data);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(String generatedAt) { this.generatedAt = generatedAt; }

    public Map<String, Object> getData() { return data; }
    public void setData(Map<String, Object> data) { this.data = data; }
}

