package org.datashield.util;

import org.datashield.config.DataShieldConfig;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Java generator for forensic disk images with embedded signatures and fragmented data.
 */
public class GenerateSampleDrive {

    public static void main(String[] args) {
        try {
            Path sampleDir = DataShieldConfig.getSampleDataDir();
            Path sandboxDir = sampleDir.resolve("sandbox");

            if (!Files.exists(sandboxDir)) {
                Files.createDirectories(sandboxDir);
            }

            // 1. Generate Sandbox Files for File & Folder Eraser
            Path file1 = sandboxDir.resolve("classified_evidence_log.txt");
            Path file2 = sandboxDir.resolve("suspect_financials.csv");
            Path file3 = sandboxDir.resolve("system_dump.log");

            Files.writeString(file1, "CONFIDENTIAL FORENSIC LOG: Suspect activity logged on 2026-09-24 at 14:32 UTC.\n");
            Files.writeString(file2, "TransactionID,Sender,Receiver,Amount,Status\nTX1001,UserA,UserB,50000,COMPLETED\nTX1002,UserC,UserD,120000,PENDING\n");
            Files.writeString(file3, "[DEBUG] System boot sequence started...\n[INFO] Interface eth0 up\n[WARN] Security alert triggered at sector 0x400\n");

            // 2. Generate sample_drive.img with binary signatures (2 MB)
            byte[] driveBuffer = new byte[2 * 1024 * 1024];
            Arrays.fill(driveBuffer, (byte) 0x00);

            // Item 1: JPEG Image at offset 0x1000
            byte[] jpgHeader = HashUtil.hexToBytes("ffd8ffe000104a46494600010101006000600000");
            byte[] jpgPayload = "DATASHIELD_FORENSIC_ACQUISITION_JPEG_PAYLOAD_SAMPLE_PHOTO_RECOVERED_SUCCESSFULLY_CASE_2026_0001".getBytes(StandardCharsets.UTF_8);
            byte[] jpgFooter = HashUtil.hexToBytes("ffd9");
            System.arraycopy(jpgHeader, 0, driveBuffer, 0x1000, jpgHeader.length);
            System.arraycopy(jpgPayload, 0, driveBuffer, 0x1000 + 20, jpgPayload.length);
            System.arraycopy(jpgFooter, 0, driveBuffer, 0x1000 + 20 + jpgPayload.length, jpgFooter.length);

            // Item 2: PDF Document at offset 0x8000
            byte[] pdfHeader = "%PDF-1.7\n%Digital Forensics Report\n1 0 obj\n<< /Title (Smart India Hackathon 2026 Forensic Case) /Author (Investigator S. Sharma) >>\nendobj\n".getBytes(StandardCharsets.US_ASCII);
            byte[] pdfFooter = "\n%%EOF\n".getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(pdfHeader, 0, driveBuffer, 0x8000, pdfHeader.length);
            System.arraycopy(pdfFooter, 0, driveBuffer, 0x8000 + pdfHeader.length + 100, pdfFooter.length);

            // Item 3: ZIP Archive at offset 0x18000
            byte[] zipHeader = HashUtil.hexToBytes("504b0304140000000800");
            byte[] zipPayload = "ZIP_ARCHIVE_CONTAINING_EVIDENCE_LOGS_2026_CASE".getBytes(StandardCharsets.US_ASCII);
            byte[] zipEocd = HashUtil.hexToBytes("504b05060000000001000100380000004f0000000000");
            System.arraycopy(zipHeader, 0, driveBuffer, 0x18000, zipHeader.length);
            System.arraycopy(zipPayload, 0, driveBuffer, 0x18000 + 10, zipPayload.length);
            System.arraycopy(zipEocd, 0, driveBuffer, 0x18000 + 10 + zipPayload.length, zipEocd.length);

            // Item 4: PNG Image (Fragmented!)
            byte[] pngHeader = HashUtil.hexToBytes("89504e470d0a1a0a0000000d4948445200000100000001000806000000");
            byte[] pngFrag1 = "PNG_FRAGMENT_1_IMAGE_DATA_HEADER_CHUNK_PASSED_INTEGRITY_CHECK_".getBytes(StandardCharsets.UTF_8);
            byte[] pngFrag2 = "PNG_FRAGMENT_2_IMAGE_DATA_BODY_CHUNK_CONTINUITY_VERIFIED_SCORE_HIGH_".getBytes(StandardCharsets.UTF_8);
            byte[] pngFrag3Header = "PNG_FRAGMENT_3_FINAL_CHUNK_".getBytes(StandardCharsets.UTF_8);
            byte[] pngFooter = HashUtil.hexToBytes("49454e44ae426082");

            System.arraycopy(pngHeader, 0, driveBuffer, 0x30000, pngHeader.length);
            System.arraycopy(pngFrag1, 0, driveBuffer, 0x30000 + 28, pngFrag1.length);
            System.arraycopy(pngFrag2, 0, driveBuffer, 0x38000, pngFrag2.length);
            System.arraycopy(pngFrag3Header, 0, driveBuffer, 0x40000, pngFrag3Header.length);
            System.arraycopy(pngFooter, 0, driveBuffer, 0x40000 + pngFrag3Header.length, pngFooter.length);

            Path imagePath = sampleDir.resolve("sample_drive.img");
            Files.write(imagePath, driveBuffer);
            String hash = HashUtil.sha256(driveBuffer);

            System.out.println("[+] Sample Drive Image Created: " + imagePath);
            System.out.println("[+] Size: " + driveBuffer.length + " bytes (2.0 MB)");
            System.out.println("[+] SHA-256 Hash: " + hash);
            System.out.println("[+] Embedded Signatures: JPEG @ 0x1000, PDF @ 0x8000, ZIP @ 0x18000, PNG @ 0x30000");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
