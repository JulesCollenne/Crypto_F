// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class AES {
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

    public static void main(String[] args) {
        try {
            fis = new FileInputStream("test");
            fos = new FileOutputStream("test_sortie");
        }
        catch (Exception e) { System.out.println("Fichier inexistant.");}
        System.out.println("Clef utilisée: 0x" + toHex(clefBrute));
        //------------------------------------------------------------------
        //  Etape 1.   Récupérer un objet qui chiffre ou déchiffre en AES
        //             dans le mode CBC (non-déterministe) avec bourrage standard.
        //------------------------------------------------------------------
        try {
            chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (Exception e) { System.out.println("AES n'est pas disponible.");}
        //------------------------------------------------------------------
        //  Etape 2.   Fabriquer la clé AES de 128 bits correspondante et
        //             préparer le vecteur d'initialisation.
        //------------------------------------------------------------------
        clefSecrète = new SecretKeySpec(clefBrute, "AES");
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        //------------------------------------------------------------------
        //  Etape 3.   Chiffrer le fichier et sauvegarder le résultat
        //------------------------------------------------------------------
        try {
            chiffreur.init(Cipher.ENCRYPT_MODE, clefSecrète, ivspec);
            cis = new CipherInputStream(fis, chiffreur);
            while ( ( nbOctetsLus = cis.read(buffer) ) != -1 ) {
                fos.write(buffer, 0, nbOctetsLus);
            }
            fos.close();
            cis.close();
            fis.close();
        } catch (Exception e) { System.out.println("Chiffrement impossible:" + e.getMessage());}
        //------------------------------------------------------------------
        //  Etape 4.   Déchiffrer en guise de test
        //------------------------------------------------------------------
        try{
            fis = new FileInputStream("test_sortie");
            fos = new FileOutputStream("test_sortie2");
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
   $ java AES butokuden.jpg butokuden_c.jpg butokuden_d.jpg
   Clef utilisée: 0x2B7E151628AED2A6ABF7158809CF4F3C
   $ ls -al
   total 2832
   drwxr--r--  11 toto  staff     374 24 jan 11:48 .
   drwxr-xr-x   6 toto  staff     204 26 oct  2016 ..
   -rw-r--r--   1 toto  staff    3340 24 jan 11:48 AES.class
   -rw-r--r--@  1 toto  staff    4319 24 jan 11:45 AES.java
   -rwxr--r--   1 toto  staff      42 18 mar  2013 Makefile
   -rw-r--r--@  1 toto  staff  467796 21 jan  2015 butokuden.jpg
   -rw-r--r--   1 toto  staff  467808 24 jan 11:48 butokuden_c.jpg
   -rw-r--r--   1 toto  staff  467796 24 jan 11:48 butokuden_d.jpg
   $ diff butokuden.jpg butokuden_d.jpg
   $
   $ openssl enc -aes-128-cbc -K 2B7E151628AED2A6ABF7158809CF4F3C -iv 00000000000000000000000000000000 \
     -in butokuden.jpg -out butokuden_c_bis.jpg
   $ diff butokuden_c.jpg butokuden_c_bis.jpg
   $
*/

/*
  Notez que butokuden_c.jpg fait 12 octets de plus que butokuden.jpg, à cause du
  bourrage et que sa taille est bien un multiple de 16.

  Notez aussi que le vecteur d'initialisation n'est pas inséré dans le chiffré.
*/
