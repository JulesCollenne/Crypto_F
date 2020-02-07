// -*- coding: utf-8 -*-

import java.io.*;
import java.util.Enumeration;

import java.security.cert.Certificate;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore;

public class RSA_JKS {
    // Pour manipuler le trousseau
    private static KeyStore magasin;
    private static final String nomDuTrousseau = "MonTrousseau.jks";
    private static final char[] motDePasse = "Alain Turin".toCharArray();
    private static KeyStore.ProtectionParameter protection;
    private static String alias;

    private static Cipher chiffreur = null;

    public static void main(String[] args) throws Exception {
        // Le chiffrement prend des octets et renvoie des octets
        System.out.println("Message clair: \"KYOTO\"");
        byte[] messageClair = "KYOTO".getBytes();
        byte[] messageChiffré = null;
        byte[] messageDéchiffré = null;
        PublicKey clefPublique = null ;
        PrivateKey clefPrivée = null;

        //------------------------------------------------------------------
        //  Etape 1.   Charger le trousseau dans le magasin
        //------------------------------------------------------------------
        FileInputStream fis = null;
        magasin = KeyStore.getInstance("JKS");
        fis = new FileInputStream(nomDuTrousseau);
        magasin.load(fis, motDePasse);
        fis.close();

        //------------------------------------------------------------------
        //  Etape 2.   Pour chiffrer, il faut la clef publique
        //------------------------------------------------------------------
        alias = "Certificat de clef publique RSA n°11";
        Certificate certificat = magasin.getCertificate(alias);
        if (certificat != null) {
            clefPublique = certificat.getPublicKey () ;
            System.out.println("Clef publique récupérée!");
        }

        //------------------------------------------------------------------
        //  Etape 3.  Chiffrer avec la clef publique RSA
        //------------------------------------------------------------------
        Cipher chiffreur = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        chiffreur.init(Cipher.ENCRYPT_MODE, clefPublique);
        messageChiffré = chiffreur.doFinal(messageClair);
        System.out.println("Message chiffré : \n" + toHex(messageChiffré));

        //------------------------------------------------------------------
        //  Etape 4.  Pour déchiffrer, il faut la clef privée RSA associée
        //------------------------------------------------------------------
        alias = "Clef privée RSA n°11";
        protection = new KeyStore.PasswordProtection(motDePasse);
        PrivateKeyEntry entréePrivée = null;
        entréePrivée = (KeyStore.PrivateKeyEntry) magasin.getEntry(alias,protection);
        if (entréePrivée != null) {
            clefPrivée = entréePrivée.getPrivateKey();
            System.out.println("Clef privée récupérée!");
            certificat = entréePrivée.getCertificate();
            System.out.println("avec la clef publique associée!");
        }

        //------------------------------------------------------------------
        //  Etape 5.  Déchiffrer avec la clef privée RSA
        //------------------------------------------------------------------
        chiffreur.init(Cipher.DECRYPT_MODE, clefPrivée);
        messageDéchiffré = chiffreur.doFinal(messageChiffré);
        System.out.println("Message déchiffré: \"" + new String(messageDéchiffré) + "\"");
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }
        return sb.toString();
    }
}

/*
   $ make
   javac *.java
   $ java RSA_JKS
   Message clair: "KYOTO"
   Clef publique récupérée!
   Message chiffré :
   436DCF9B58D3041A8DF0BD64A82166C2BC19A19B8086BB8B30...6CA
   Clef privée récupérée!
   avec la clef publique associée!
   Message déchiffré: "KYOTO"
   $
 */
