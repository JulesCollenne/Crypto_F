import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class q1 {

    private static final byte[] clefBrute = { // 16 octets
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    private static Cipher chiffreur;
    private static SecretKeySpec clefSecrète;

    private static byte[] buffer = new byte[1024];
    private static int nbOctetsLus;
    private static FileInputStream fis;
    private static FileOutputStream fos;
    private static CipherInputStream cis;

    public static void main(String[] args){
        try {
            chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (Exception e) { System.out.println("AES n'est pas disponible.");}
        clefSecrète = new SecretKeySpec(clefBrute, "AES");
        byte[] iv = { (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        try{
            fis = new FileInputStream("mystere");
            fos = new FileOutputStream("mystere_decode.jpg");
        }
        catch (Exception e) { System.out.println("Fichier inexistant:"+ e.getMessage());}
        try {
            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrète, ivspec);
            cis = new CipherInputStream(fis, chiffreur);
            while ( ( nbOctetsLus = cis.read(buffer) ) != -1 ) {
                fos.write(buffer, 0, nbOctetsLus);
            }
            fos.close();
            cis.close();
            fis.close();
        } catch (Exception e) { System.out.println("Déchiffrement impossible:"+ e.getMessage());}
    }

}
