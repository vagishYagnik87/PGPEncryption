package controller;

import utils.Utils;

import java.io.*;

public enum BaseController {

    INSTANCE;

    private static final String passkey = "!hic6@7qEM2z4yF";
    private static final String privateKeyPath = "src/main/resources/private.pgp";
    private static final String publicKeyPath = "src/main/resources/public.pgp";
    private static final String path = "src/main/resources/file.txt";
    private static final String encPath = "src/main/resources/enc.txt";
    private static final String decPath = "src/main/resources/dec.txt";

    public void encrypt() throws FileNotFoundException {
        Utils.INSTANCE.encrypt(new FileOutputStream(encPath), new FileInputStream(path), new FileInputStream(publicKeyPath));
    }

    public void decrypt() throws FileNotFoundException {
        Utils.INSTANCE.decrypt(new FileInputStream(encPath), new FileOutputStream(decPath), new FileInputStream(privateKeyPath), passkey);
    }
}
