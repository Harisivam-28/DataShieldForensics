package org.datashield.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class Device {
    private String id;
    private String name;
    private String type;
    private String capacity;
    private long capacityBytes;
    private String filesystem;
    private String partitionInfo;
    private String sectorSize;
    private String mountStatus;
    private boolean readOnlyStatus;
    private boolean removable;
    private boolean isSystemDisk;
    private String recommendedWorkflow;
    private String devicePath;

    public Device() {}

    public static Device fromMap(Map<String, Object> map) {
        Device d = new Device();
        if (map == null) return d;
        d.id = (String) map.get("id");
        d.name = (String) map.get("name");
        d.type = (String) map.get("type");
        d.capacity = (String) map.get("capacity");
        Object cb = map.get("capacityBytes");
        d.capacityBytes = cb instanceof Number ? ((Number) cb).longValue() : 0L;
        d.filesystem = (String) map.get("filesystem");
        d.partitionInfo = (String) map.get("partitionInfo");
        d.sectorSize = (String) map.get("sectorSize");
        d.mountStatus = (String) map.get("mountStatus");
        d.readOnlyStatus = Boolean.TRUE.equals(map.get("readOnlyStatus"));
        d.removable = Boolean.TRUE.equals(map.get("removable"));
        d.isSystemDisk = Boolean.TRUE.equals(map.get("isSystemDisk"));
        d.recommendedWorkflow = (String) map.get("recommendedWorkflow");
        d.devicePath = (String) map.get("devicePath");
        return d;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("name", name);
        map.put("type", type);
        map.put("capacity", capacity);
        map.put("capacityBytes", capacityBytes);
        map.put("filesystem", filesystem);
        map.put("partitionInfo", partitionInfo);
        map.put("sectorSize", sectorSize);
        map.put("mountStatus", mountStatus);
        map.put("readOnlyStatus", readOnlyStatus);
        map.put("removable", removable);
        map.put("isSystemDisk", isSystemDisk);
        map.put("recommendedWorkflow", recommendedWorkflow);
        map.put("devicePath", devicePath);
        return map;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getCapacity() { return capacity; }
    public void setCapacity(String capacity) { this.capacity = capacity; }

    public long getCapacityBytes() { return capacityBytes; }
    public void setCapacityBytes(long capacityBytes) { this.capacityBytes = capacityBytes; }

    public String getFilesystem() { return filesystem; }
    public void setFilesystem(String filesystem) { this.filesystem = filesystem; }

    public String getPartitionInfo() { return partitionInfo; }
    public void setPartitionInfo(String partitionInfo) { this.partitionInfo = partitionInfo; }

    public String getSectorSize() { return sectorSize; }
    public void setSectorSize(String sectorSize) { this.sectorSize = sectorSize; }

    public String getMountStatus() { return mountStatus; }
    public void setMountStatus(String mountStatus) { this.mountStatus = mountStatus; }

    public boolean isReadOnlyStatus() { return readOnlyStatus; }
    public void setReadOnlyStatus(boolean readOnlyStatus) { this.readOnlyStatus = readOnlyStatus; }

    public boolean isRemovable() { return removable; }
    public void setRemovable(boolean removable) { this.removable = removable; }

    public boolean isSystemDisk() { return isSystemDisk; }
    public void setSystemDisk(boolean systemDisk) { isSystemDisk = systemDisk; }

    public String getRecommendedWorkflow() { return recommendedWorkflow; }
    public void setRecommendedWorkflow(String recommendedWorkflow) { this.recommendedWorkflow = recommendedWorkflow; }

    public String getDevicePath() { return devicePath; }
    public void setDevicePath(String devicePath) { this.devicePath = devicePath; }
}

