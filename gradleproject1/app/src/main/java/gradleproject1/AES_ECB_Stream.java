package gradleproject1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES_ECB_Stream {
     // 32 byte = 256 bit key length
    public static void encrypt(File plainFile,byte[] KEY) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
      
        // Encryption and Dencryption must be separate in different method
        // Encryption method need to pass File plainFile
        // Dencryption method neet to pass File cihperFile

        // Encryption:
        String cihperFile = plainFile.getParent() + "\\" + plainFile.getName().replaceFirst("[.][^.]+$", "") + ".enc";
        encryptWitEcb(plainFile.getAbsolutePath(), cihperFile, KEY);
        //System.out.println("file used for encryption: " + plainFile.getAbsolutePath());
        //System.out.println("created encrypted file  : " + cihperFile);


        // Dencryption:
        // String decryptedFile = cihperFile.getParent() + "\\" + cihperFile.getName().replaceFirst("[.][^.]+$", "") + ".enc"
        //               (**********NOTE: We need a way to find out the extension of the file decryptedFile  ----->   ^^^^^^^

        // decryptWithEcb(cihperFile.getAbsolutePath(), decryptedFile, key);
        // System.out.println("file used for dencryption: " + cihperFile.getAbsolutePath());
        // System.out.println("created decrypted file  : " + decryptedFile);


        //System.out.println("AES ECB Stream Encryption ended");
    }
    
    public static void decrypt(File plainFile, byte[] KEY,String extenstion) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        
        // Encryption and Dencryption must be separate in different method
        // Encryption method need to pass File plainFile
        // Dencryption method neet to pass File cihperFile

        // Encryption:
        //String cihperFile = plainFile.getParent() + "\\" + plainFile.getName().replaceFirst("[.][^.]+$", "") + ".enc";
        //encryptWitEcb(plainFile.getAbsolutePath(), cihperFile, KEY);
        //System.out.println("file used for encryption: " + plainFile.getAbsolutePath());
        //System.out.println("created encrypted file  : " + cihperFile);


        // Dencryption:
        String decryptedFile = plainFile.getParent() + "\\" + plainFile.getName().replaceFirst("[.][^.]+$", "") + extenstion;
        //               (**********NOTE: We need a way to find out the extension of the file decryptedFile  ----->   ^^^^^^^

        decryptWithEcb(plainFile.getAbsolutePath(), decryptedFile, KEY);
         System.out.println("file used for dencryption: " + plainFile.getAbsolutePath());
         System.out.println("created decrypted file  : " + decryptedFile);


        System.out.println("AES ECB Stream Encryption ended");
    }
    
    public static void BruteForce(File plainFile, byte[] KEY,String extenstion) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        
        // Encryption and Dencryption must be separate in different method
        // Encryption method need to pass File plainFile
        // Dencryption method neet to pass File cihperFile

        // Encryption:
        //String cihperFile = plainFile.getParent() + "\\" + plainFile.getName().replaceFirst("[.][^.]+$", "") + ".enc";
        //encryptWitEcb(plainFile.getAbsolutePath(), cihperFile, KEY);
        //System.out.println("file used for encryption: " + plainFile.getAbsolutePath());
        //System.out.println("created encrypted file  : " + cihperFile);


        // Dencryption:
        String decryptedFile = plainFile.getParent() + "\\" + plainFile.getName().replaceFirst("[.][^.]+$", "") + extenstion;
        //               (**********NOTE: We need a way to find out the extension of the file decryptedFile  ----->   ^^^^^^^
        try{
        decryptWithEcb(plainFile.getAbsolutePath(), decryptedFile, KEY);
         System.out.println("file used for dencryption: " + plainFile.getAbsolutePath());}
        catch (BadPaddingException a){
            System.out.println(a+"=====================================");
            File f = new File(decryptedFile);
            f.delete();
        }
         System.out.println("created decrypted file  : " + decryptedFile);


        System.out.println("AES ECB Stream Encryption ended");
    }

    public static void encryptWitEcb(String filenamePlain, String filenameEnc, byte[] key) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        try (FileInputStream fis = new FileInputStream(filenamePlain);
             BufferedInputStream in = new BufferedInputStream(fis);
             FileOutputStream out = new FileOutputStream(filenameEnc);
             BufferedOutputStream bos = new BufferedOutputStream(out)) {
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    bos.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                bos.write(obuf);
        }
    }

    public static void decryptWithEcb(String filenameEnc, String filenameDec, byte[] key) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        try (FileInputStream in = new FileInputStream(filenameEnc);
             FileOutputStream out = new FileOutputStream(filenameDec)) {
            byte[] ibuf = new byte[1024];
            int len;
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    out.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                out.write(obuf);
        }
    }
}