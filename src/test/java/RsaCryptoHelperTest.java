/**
 * Created by TAABOAM1 on 27.01.2015.
 */

import com.swisscom.scsapi.commons.crypto.RsaCryptoHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import static org.junit.Assert.assertEquals;

public class RsaCryptoHelperTest {

    /**
     * File path to the private key.
     */
    private String filePathToPrivateKey = "src/main/resources/private.key";

    /**
     * File path to the public key.
     */
    private String filePathToPublicBase64Key = "src/main/resources/public.key";

    /**
     * Example to demonstrate how to create an encrypt a secret. It also demonstrates how to decrypt the secret.
     * @throws UnsupportedEncodingException
     */
    @Test
    public void shouldEncryptSecret() throws UnsupportedEncodingException {
        //Init
        String myUUID = "uuid-1234567890";
        String secret = createSecret(myUUID);

        //Encrypt
        String privateKeyBase64 = readKey(new File(filePathToPrivateKey));
        String encryptedSecret = RsaCryptoHelper.encryptValueWithPrivateKey(privateKeyBase64, secret);
        String encryptedSecretURLencoded = URLEncoder.encode(encryptedSecret, "UTF-8");

        //Decrypt
        String publicKeyBase64 = readKey(new File(filePathToPublicBase64Key));
        String encryptedSecretURLdecoded = URLDecoder.decode(encryptedSecretURLencoded, "UTF-8");
        String decryptedSecret = RsaCryptoHelper.decryptValueWithPublicKey(publicKeyBase64, encryptedSecretURLdecoded);

        assertEquals(secret, decryptedSecret);
    }

    /**
     * Creates the secret based on the UUID.
     * @param aUUID the UUID
     * @return Secret in the appropriate format. It contains the UUID and the timestamp.
     */
    private String createSecret(final String aUUID) {
        return aUUID + ":" + System.currentTimeMillis();
    }

    /**
     * Reads the key.
     * @param aFilepathToKey The file path to the key
     * @return Base64 encoded key
     */
    private String readKey(File aFilepathToKey) {
        byte[] key = null;

        try {
            key = FileUtils.readFileToByteArray(aFilepathToKey);
        } catch (Exception exception) {
            //TODO handle exception
        }

        return new Base64().encodeAsString(key);
    }



}

