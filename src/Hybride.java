import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Enumeration;

public class Hybride {

    private static KeyStore magasin;
    private static final String nomDuTrousseau = "Trousseau.p12";
    private static final char[] motDePasse = "Alain Turin".toCharArray();
    private static KeyStore.ProtectionParameter protection;

    private static Cipher chiffreur = null;

    public static void main(String[] args){
        byte[] messageChiffré = new byte[0];
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
                        //System.out.println("La clef est : " + entréePrivée.getPrivateKey());
                        decrypte(entréePrivée, messageChiffré, "RSA/ECB/PKCS1Padding");
                        decrypte(entréePrivée, messageChiffré, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                        decrypte(entréePrivée, messageChiffré, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    }
                }
            } catch (java.lang.UnsupportedOperationException e){
                e.printStackTrace();
                //System.exit(-1);
            } catch(Exception e){
                e.printStackTrace();
            }
        }
    }

    public static void decrypte(KeyStore.PrivateKeyEntry entréePrivée, byte[] messageChiffré, String algo){
        PrivateKey clefPrivée;
        byte[] messageDéchiffré;
        try {
            chiffreur = Cipher.getInstance(algo);
            clefPrivée = entréePrivée.getPrivateKey();
            chiffreur.init(Cipher.DECRYPT_MODE, clefPrivée);
            try {
                messageDéchiffré = chiffreur.doFinal(messageChiffré);
            } catch(Exception e){
                return;
            }
            if(messageDéchiffré.length == 16 || messageDéchiffré.length == 24 || messageDéchiffré.length == 32)
                System.out.println("Message déchiffré: \"" + toHex(messageDéchiffré) + "\"");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            //e.printStackTrace();
            //System.exit(-1);
        }
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }
        return sb.toString();
    }

}
