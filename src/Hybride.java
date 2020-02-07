import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;

public class Hybride {

    private static KeyStore magasin;
    private static final String nomDuTrousseau = "Trousseau.p12";
    private static final char[] motDePasse = "Alain Turin".toCharArray();
    private static KeyStore.ProtectionParameter protection;

    private static Cipher chiffreur = null;

    public static void main(String[] args){
        ArrayList<byte[]> clefs = trouveClefs();
        for (byte[] clef : clefs) System.out.println(toHex(clef));
        decrypte(clefs);
    }

    public static void decrypte(ArrayList<byte[]> clefs){
        FileInputStream fis = null;
        FileOutputStream fos = null;
        CipherInputStream cis = null;
        byte[] iv = new byte[16];
        try{
            fis = new FileInputStream("mystere2");
            fos = new FileOutputStream("mystere_sortie2");
            fis.read(iv);
        }
        catch (Exception e) {
            System.out.println("Fichier inexistant:"+ e.getMessage());
            System.exit(0);
        }

        IvParameterSpec ivspec = new IvParameterSpec(iv);
        SecretKeySpec clefSecrète;

        try {
            chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (Exception e) { System.out.println("AES n'est pas disponible.");}

        try {
            for (byte[] clef : clefs) {
                try {
                    chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
                }
                catch (Exception e) { System.out.println("AES n'est pas disponible.");}
                decrypteFichier(clef, ivspec, cis, fos, fis);
                try {
                    chiffreur = Cipher.getInstance("AES/ECB/PKCS5Padding");
                }
                catch (Exception e) { System.out.println("AES n'est pas disponible.");}
                decrypteFichier(clef, ivspec, cis, fos, fis);
                try {
                    chiffreur = Cipher.getInstance("AES/CFB/PKCS5Padding");
                }
                catch (Exception e) { System.out.println("AES n'est pas disponible.");}
                decrypteFichier(clef, ivspec, cis, fos, fis);
                try {
                    chiffreur = Cipher.getInstance("AES/OFB/PKCS5Padding");
                }
                catch (Exception e) { System.out.println("AES n'est pas disponible.");}
                decrypteFichier(clef, ivspec, cis, fos, fis);
                try {
                    chiffreur = Cipher.getInstance("AES/CTR/PKCS5Padding");
                }
                catch (Exception e) { System.out.println("AES n'est pas disponible.");}
                decrypteFichier(clef, ivspec, cis, fos, fis);
            }
            fos.close();
            cis.close();
            fis.close();
        } catch (Exception e) { System.out.println("Déchiffrement impossible:"+ e.getMessage());}
    }

    public static void decrypteFichier(byte[] clef, IvParameterSpec ivspec, CipherInputStream cis, FileOutputStream fos, FileInputStream fis){
        int nbOctetsLus;
        byte[] buffer = new byte[1024];
        SecretKeySpec clefSecrète = new SecretKeySpec(clef, "AES");

        try {
            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrète, ivspec);
            cis = new CipherInputStream(fis, chiffreur);
            while ((nbOctetsLus = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, nbOctetsLus);
            }
        } catch(Exception e){
            e.printStackTrace();
            System.exit(0);
        }
        System.out.println(cis);
    }

    public static ArrayList<byte[]> trouveClefs(){
        byte[] messageChiffré = new byte[0];
        ArrayList<byte[]> clefsPossibles = new ArrayList<>();
        try {
            messageChiffré = Files.readAllBytes(new File("clef_chiffree").toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        FileInputStream fis;
        Enumeration<String> tousLesAliases = null;

        try {
            magasin = KeyStore.getInstance("JKS");
            fis = new FileInputStream(nomDuTrousseau);
            magasin.load(fis, motDePasse);
            fis.close();
            tousLesAliases = magasin.aliases();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        KeyStore.PrivateKeyEntry entréePrivée = null;
        String alias;

        while(tousLesAliases.hasMoreElements()){
            try {
                alias = tousLesAliases.nextElement();
                protection = new KeyStore.PasswordProtection(motDePasse);
                try {
                    if (magasin.getEntry(alias, protection) instanceof KeyStore.PrivateKeyEntry)
                        entréePrivée = (KeyStore.PrivateKeyEntry) magasin.getEntry(alias, protection);
                } catch(Exception e){

                }
                if(entréePrivée != null) {
                    if (magasin.isKeyEntry(alias)) {
                        byte[] tmp;
                        //System.out.println("La clef est : " + entréePrivée.getPrivateKey());
                        tmp = decrypteClef(entréePrivée, messageChiffré, "RSA/ECB/PKCS1Padding");
                        if(tmp != null)
                            clefsPossibles.add(tmp);
                        tmp = decrypteClef(entréePrivée, messageChiffré, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                        if(tmp != null)
                            clefsPossibles.add(tmp);
                        tmp = decrypteClef(entréePrivée, messageChiffré, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                        if(tmp != null)
                            clefsPossibles.add(tmp);
                    }
                }
            } catch (java.lang.UnsupportedOperationException e){
                e.printStackTrace();
                //System.exit(-1);
            } catch(Exception e){
                e.printStackTrace();
            }
        }
        return clefsPossibles;
    }

    public static byte[] decrypteClef(KeyStore.PrivateKeyEntry entréePrivée, byte[] messageChiffré, String algo){
        PrivateKey clefPrivée;
        byte[] messageDéchiffré;
        try {
            chiffreur = Cipher.getInstance(algo);
            clefPrivée = entréePrivée.getPrivateKey();
            chiffreur.init(Cipher.DECRYPT_MODE, clefPrivée);
            try {
                messageDéchiffré = chiffreur.doFinal(messageChiffré);
            } catch(Exception e){
                return null;
            }
            if(messageDéchiffré.length == 16 || messageDéchiffré.length == 24 || messageDéchiffré.length == 32) {
                //System.out.println("Message déchiffré: \"" + toHex(messageDéchiffré) + "\"");
                return messageDéchiffré;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            //e.printStackTrace();
            //System.exit(-1);
        }
        return null;
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }
        return sb.toString();
    }

}
