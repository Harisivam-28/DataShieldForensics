package org.datashield;

import org.datashield.config.DataShieldConfig;
import org.datashield.server.DataShieldHttpServer;
import org.datashield.test.DataShieldTestSuite;

public class DataShieldApplication {

    public static void main(String[] args) {
        System.out.println("================================================================================");
        System.out.println("  DataShield Forensics Engine (Java 17)");
        System.out.println("  Integrated Secure Data Erasure & Advanced Digital Forensics Engine");
        System.out.println("================================================================================");

        if (args.length > 0 && ("--test".equalsIgnoreCase(args[0]) || "test".equalsIgnoreCase(args[0]))) {
            System.out.println("[*] Running automated test suite...");
            DataShieldTestSuite.main(new String[0]);
            return;
        }

        int port = DataShieldConfig.getPort();
        for (int i = 0; i < args.length; i++) {
            if ("--port".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                try {
                    port = Integer.parseInt(args[i + 1]);
                } catch (NumberFormatException ignored) {}
            }
        }

        try {
            DataShieldHttpServer server = new DataShieldHttpServer(port);
            server.start();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n[*] Shutting down DataShield Forensics server...");
                server.stop();
            }));

            System.out.println("[*] Web UI & API available at: http://localhost:" + port);
            System.out.println("[*] Health Check: http://localhost:" + port + "/health");
            System.out.println("[*] Press Ctrl+C to stop.");

        } catch (Exception e) {
            System.err.println("[!] Fatal Error starting DataShield server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

