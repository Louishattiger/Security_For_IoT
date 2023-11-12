import javacard.framework.*;

public class HelloWorld extends Applet {
    // Définition de l'INS (Instruction Code) pour les commandes
    private final static  byte VERIFY_PIN= (byte)0x10;
    private final static  byte CHANGE_PIN= (byte)0x11;

    // Longueur maximale du PIN
    final static byte PIN_LENGTH = (byte)0x04;
    // Le PIN est "1234"
    private final byte[] correctPIN = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};

    private final static  byte Nbre_essai_pin = 0x03;     

    OwnerPIN pin;

    protected HelloWorld()
    {
       register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorld();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] != 0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buffer[ISO7816.OFFSET_INS] == VERIFY_PIN) {
            verifyPIN(apdu);
        } else if (buffer[ISO7816.OFFSET_INS] == CHANGE_PIN) {
            changePIN(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        
        if (pinLength != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Comparer le PIN fourni avec le PIN correct
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, correctPIN, (short) 0, PIN_LENGTH) != 0) {
            ISOException.throwIt((short) 0x6300); // Code d'erreur personnalisé pour PIN incorrect
        }else{
           ISOException.throwIt((short) 0x9000);
        }
    }

    private void changePIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        
        if (pinLength != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Mettre à jour le PIN avec le nouveau PIN fourni
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, correctPIN, (short) 0, PIN_LENGTH);
    }
}