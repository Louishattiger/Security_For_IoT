package com.sun.javacard.samples.SecureApplet;

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
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecureApplet();
    }

    public SecureApplet() {
    	register();
        byte[] pinCode = {(byte) 1, (byte) 2, (byte) 3, (byte) 4}; 
        pin = new OwnerPIN(MAX_PIN_TRIES, (byte) 4);
        pin.update(pinCode, (short) 0, (byte) 4);
		
	// On génère la keypair pour obtenir la clé privée et publique
        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();   
        // On initialise l'objet signer avec l'algorithme de signature   
        signer = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false); 
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        // on vérifie si le pin est bon
        if (buffer[ISO7816.OFFSET_INS] == VERIFY_PIN_INS) {
            verifyPIN(apdu);
        // on change le pin
        } else if (buffer[ISO7816.OFFSET_INS] == CHANGE_PIN_INS) {
            changePIN(apdu);
        // on signe les données
        } else if (buffer[ISO7816.OFFSET_INS] == SIGN_DATA_INS) {
            sign_data(apdu);
		// on envoie la clé publique
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
		short dataLength = apdu.setIncomingAndReceive();
		short offset = ISO7816.OFFSET_CDATA;
		
		// initialisation pour effectuer une opération de signature avec la clé privée
		signer.init(privateKey, Signature.MODE_SIGN);
		short signatureLength = signer.sign(buffer, offset, dataLength, buffer, (short) 0);
		
		// envoie la signature dans la réponse APDU
		apdu.setOutgoingAndSend((short) 0, signatureLength);
    }
    
    private void sendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;       
        
        // Récupérer la longueur de l'exposant de la clé publique
        short expLen = publicKey.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        
        // Récupérer le modulo (la partie principale) de la clé publique
        short modLen = publicKey.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);
        
        // Envoyer les données de la clé publique
        apdu.setOutgoingAndSend(offset, (short) (4 + expLen + modLen));
    }
}
