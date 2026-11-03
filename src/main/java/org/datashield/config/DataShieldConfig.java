package org.datashield.config;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class DataShieldConfig {
    private DataShieldConfig() {}

    public static final String APP_NAME = "DataShield Forensics";
    public static final String VERSION = "1.0.0-SIH2026";
    public static final int DEFAULT_PORT = 5001;

    public static int getPort() {
        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                return Integer.parseInt(envPort.trim());
            } catch (NumberFormatException ignored) {}
        }
        return DEFAULT_PORT;
    }

    public static Path getBaseDir() {
        String appDir = System.getProperty("user.dir");
        return Paths.get(appDir);
    }

    public static Path getSampleDataDir() {
        Path p = getBaseDir().resolve("sample_data");
        if (!p.toFile().exists()) {
            // Check Contents/Resources/app/sample_data fallback
            Path alt = getBaseDir().resolve("Contents/Resources/app/sample_data");
            if (alt.toFile().exists()) return alt;
        }
        return p;
    }

    public static Path getSandboxDir() {
        return getSampleDataDir().resolve("sandbox");
    }

    public static Path getSampleImagePath() {
        return getSampleDataDir().resolve("sample_drive.img");
    }

    public static Path getFrontendDistDir() {
        Path p = getBaseDir().resolve("frontend/dist");
        if (!p.toFile().exists()) {
            Path alt = getBaseDir().resolve("Contents/Resources/app/frontend/dist");
            if (alt.toFile().exists()) return alt;
        }
        return p;
    }

    public static Path getDbFilePath() {
        String customDb = System.getenv("DB_PATH");
        if (customDb != null && !customDb.isBlank()) {
            return Paths.get(customDb);
        }
        return getBaseDir().resolve("datashield_db.json");
    }
}

