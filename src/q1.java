import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class q1 {

    private static final byte[] clefBrute = { // 16 octets
            (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
            (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
            (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
            (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c };
    private static Cipher chiffreur;
    private static SecretKeySpec clefSecrète;

    private static byte[] buffer = new byte[1024];
    private static int nbOctetsLus;
    private static FileInputStream fis;
    private static FileOutputStream fos;
    private static CipherInputStream cis;

    public static void main(String[] args){
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        try{
            fis = new FileInputStream(args[1]);
            fos = new FileOutputStream(args[2]);
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
