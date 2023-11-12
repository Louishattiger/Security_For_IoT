ackage com.sun.javacard.samples.SecureApplet;

import javacard.framework.*;
import javacard.security.*;

public class SecureApplet extends Applet {

    private static final byte VERIFY_PIN_INS = (byte) 0x20;
    private static final byte CHANGE_PIN_INS = (byte) 0x30;
    private static final byte SIGN_DATA_INS = (byte) 0x40;
    private static final byte GET_PUBLIC_KEY_INS = (byte) 0x50;
    private static final byte MAX_PIN_TRIES = 3;
    
    private OwnerPIN pin;

    RSAPrivateKey privateKey;
    RSAPublicKey  publicKey;
    KeyPair keyPair;
    Signature signer;

    byte [] sig_array = new byte [255];
    short len;
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecureApplet();
    }

    public SecureApplet() {
        register();
        byte[] pinCode = {(byte) 1, (byte) 2, (byte) 3, (byte) 4}; 
        pin = new OwnerPIN(MAX_PIN_TRIES, (byte) 4);
        pin.update(pinCode, (short) 0, (byte) 4);

        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();      
        signer = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false); 
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_INS] == VERIFY_PIN_INS) {
            verifyPIN(apdu);
        } else if (buffer[ISO7816.OFFSET_INS] == CHANGE_PIN_INS) {
            changePIN(apdu);
        } else if (buffer[ISO7816.OFFSET_INS] == SIGN_DATA_INS) {
            sign_data(apdu);
        } else if (buffer[ISO7816.OFFSET_INS] == GET_PUBLIC_KEY_INS) {
            sendPublicKey(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short pinLength = apdu.setIncomingAndReceive();

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) pinLength)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void changePIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short pinLength = apdu.setIncomingAndReceive();

        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (pinLength != 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) pinLength);
    }

    private void sign_data(APDU   apdu){
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;

        try{
            signer.init(privateKey, Signature.MODE_SIGN);;
            signer.update(buffer, offset, buffer[ISO7816.OFFSET_LC]);

            short signature = signer.sign(buffer, offset, Util.getShort(buffer,ISO7816.OFFSET_LC), sig_array, (short)0);;
            apdu.setOutgoingAndSend(offset, signature);
            //Util.arrayCopyNonAtomic(signature, (short) 0, buffer, offset, (short) signature.length);
        }
        catch(Exception e) {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }    
    }
    
    private void sendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;       
        
        // Recuperer la longueur de l'exposant de la cle  publique
        short expLen = publicKey.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        
        // Recuperer le modulo (la partie principale) de la cle  publique
        short modLen = publicKey.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);
        
        // Envoyer les donnees de la cle publique
        apdu.setOutgoingAndSend(offset, (short) (4 + expLen + modLen));
    }
}
