package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class Case {
    private String id;
    private String name;
    private String investigator;
    private String organization;
    private String description;
    private String createdDate;
    private String caseType; // Forensic Investigation | Data Sanitization | Combined
    private String status;

    public Case() {}

    public Case(String id, String name, String investigator, String organization, String description, String createdDate, String caseType, String status) {
        this.id = id;
        this.name = name;
        this.investigator = investigator;
        this.organization = organization;
        this.description = description;
        this.createdDate = createdDate;
        this.caseType = caseType;
        this.status = status;
    }

    public static Case fromMap(Map<String, Object> map) {
        Case c = new Case();
        if (map == null) return c;
        c.id = (String) map.get("id");
        c.name = (String) map.get("name");
        c.investigator = (String) map.get("investigator");
        c.organization = (String) map.get("organization");
        c.description = (String) map.get("description");
        c.createdDate = (String) map.get("createdDate");
        c.caseType = (String) map.get("caseType");
        c.status = (String) map.get("status");
        return c;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("name", name);
        map.put("investigator", investigator);
        map.put("organization", organization);
        map.put("description", description);
        map.put("createdDate", createdDate);
        map.put("caseType", caseType);
        map.put("status", status);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getInvestigator() { return investigator; }
    public void setInvestigator(String investigator) { this.investigator = investigator; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getCreatedDate() { return createdDate; }
    public void setCreatedDate(String createdDate) { this.createdDate = createdDate; }

    public String getCaseType() { return caseType; }
    public void setCaseType(String caseType) { this.caseType = caseType; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}

