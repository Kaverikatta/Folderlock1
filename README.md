# Folderlock1
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class FolderUnlock {

    private static final String AES_ALGORITHM = "AES";
    private static final String SECRET_KEY_ALGORITHM = "AES";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the locked folder path: ");
        String folderPath = scanner.nextLine();

        System.out.print("Enter the password: ");
        String password = scanner.nextLine();

        unlockFolder(folderPath, password);

        System.out.println("Folder unlocked successfully.");
    }

    public static void unlockFolder(String folderPath, String password) {
        try {
            // Generate a secret key from the password
            byte[] key = generateKey(password);

            // Decrypt all files in the folder
            decryptFiles(folderPath, key);

            // Rename the folder to remove the ".locked" extension
            File folder = new File(folderPath);
            String unlockedFolderPath = folder.getParent() + File.separator + folder.getName().replace(".locked", "");
            File unlockedFolder = new File(unlockedFolderPath);
            folder.renameTo(unlockedFolder);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateKey(String password) throws Exception {
        // Generate a 256-bit key from the password using SHA-256
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(password.getBytes("UTF-8"));

        // Use only the first 128 bits as the secret key
        return Arrays.copyOf(keyBytes, 16);
    }

    private static void decryptFiles(String folderPath, byte[] key) throws Exception {
        File folder = new File(folderPath);
        File[] files = folder.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    decryptFiles(file.getAbsolutePath(), key);  // Recursively decrypt subfolders
                } else {
                    decryptFile(file, key);
                }
            }
        }
    }

    private static void decryptFile(File file, byte[] key) throws Exception {
        // Read the file contents into a byte array
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        // Create a cipher instance and initialize it with the secret key
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Decrypt the file contents
        byte[] decryptedBytes = cipher.doFinal(fileBytes);

        // Write the decrypted bytes back to the file
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(decryptedBytes);
        }
    }
}
