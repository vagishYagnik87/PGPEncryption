package utils.encryption;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import utils.Utils;

import java.io.*;
import java.nio.charset.Charset;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;

public class PgpDecryptionUtil {

    static {
        // Add Bouncy castle to JVM
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final char[] passCode;
    private final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;

    public PgpDecryptionUtil(InputStream privateKeyIn, String passCode) throws IOException, PGPException {
        this.passCode = passCode.toCharArray();
        this.pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn)
                , new JcaKeyFingerprintCalculator());
    }

    public PgpDecryptionUtil(String privateKeyStr, String passCode) throws IOException, PGPException {
        this(IOUtils.toInputStream(privateKeyStr, Charset.defaultCharset()), passCode);
    }


    private PGPPrivateKey findSecretKey(long keyID) throws PGPException {
        PGPSecretKey pgpSecretKey = pgpSecretKeyRingCollection.getSecretKey(keyID);
        return pgpSecretKey == null ? null : pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passCode));
    }

    public void decrypt(InputStream encryptedIn, OutputStream clearOut)
            throws PGPException, IOException {
        // Removing armour and returning the underlying binary encrypted stream
        encryptedIn = PGPUtil.getDecoderStream(encryptedIn);
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedIn);

        Object obj = pgpObjectFactory.nextObject();
        //The first object might be a marker packet
        PGPEncryptedDataList pgpEncryptedDataList = (obj instanceof PGPEncryptedDataList)
                ? (PGPEncryptedDataList) obj : (PGPEncryptedDataList) pgpObjectFactory.nextObject();

        PGPPrivateKey pgpPrivateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

        Iterator<PGPEncryptedData> encryptedDataItr = pgpEncryptedDataList.getEncryptedDataObjects();
        while (pgpPrivateKey == null && encryptedDataItr.hasNext()) {
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataItr.next();
            pgpPrivateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
        }

        if (Objects.isNull(publicKeyEncryptedData)) {
            throw new PGPException("Could not generate PGPPublicKeyEncryptedData object");
        }

        if (pgpPrivateKey == null) {
            throw new PGPException("Could Not Extract private key");
        }
        Utils.INSTANCE.decrypt(clearOut, pgpPrivateKey, publicKeyEncryptedData);
    }

    public byte[] decrypt(byte[] encryptedBytes) throws PGPException, IOException {
        ByteArrayInputStream encryptedIn = new ByteArrayInputStream(encryptedBytes);
        ByteArrayOutputStream clearOut = new ByteArrayOutputStream();
        decrypt(encryptedIn, clearOut);
        return clearOut.toByteArray();
    }
}