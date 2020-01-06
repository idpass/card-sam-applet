/*
 * Copyright (C) 2019 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.idpass.sam;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.idpass.tools.IdpassApplet;
import org.idpass.tools.SIOAuthListener;
import org.idpass.tools.Utils;

public class SamApplet extends IdpassApplet implements SIOAuthListener {

    // INS
    // ISO

    // Encrypt data with personas slot. No security
    private static final byte  INS_ENCRYPT  = (byte) 0xEC;
    private static final byte  P1_ENCRYPT   = (byte) 0x00;
    private static final byte  P2_ENCRYPT   = (byte) 0x00;

    // Decrypt data with personas slot. No security
    private static final byte  INS_DECRYPT  = (byte) 0xDC;
    private static final byte  P1_DECRYPT   = (byte) 0x00;
    private static final byte  P2_DECRYPT   = (byte) 0x00;

    private static final short NO_OPEN_SLOT = (short) 0xFFFF;
    
    

    public static void install(byte[] bArray, short bOffset, byte bLength) {

        byte lengthAID = bArray[bOffset];
        short offsetAID = (short) (bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        // default params

        byte secret = DEFAULT_SECRET;

        // read params
        short lengthIn = bArray[offset];
        if (lengthIn != 0) {

            if (1 <= lengthIn) {
                // param 1 - not mandatory
                secret = bArray[(short) (offset + 1)];
            }

        }

        // GP-compliant JavaCard applet registration
        SamApplet applet = new SamApplet(secret);
        applet.register(bArray, offsetAID, lengthAID);
    }

    // default secret for SIO
    private static final byte DEFAULT_SECRET = (byte) 0x9E;

    // instance fields
    private byte              secret;
    private SlotsRepository   slotsRepository;

    public SamApplet(byte secret) {
        this.secret = secret;
        slotsRepository = SlotsRepository.create();
    }
    
    protected SamApplet(byte[] bArray, short bOffset, byte bLength) {

        byte lengthAID = bArray[bOffset];
        short offsetAID = (short) (bOffset + 1);
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        // default params

        byte secret = DEFAULT_SECRET;

        // read params
        short lengthIn = bArray[offset];
        if (lengthIn != 0) {

            if (1 <= lengthIn) {
                // param 1 - not mandatory
                secret = bArray[(short) (offset + 1)];
            }

        }

        this.aid_offset = offsetAID ;
        this.aid_len = lengthAID;

        this.secret = secret;
        slotsRepository = SlotsRepository.create();
    }

    /**
     * Shareable interface standart call from JCOP
     */
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (secret != parameter)
            return null;

        return (SIOAuthListener) this;
    }

    public void onPersonaAdded(short personaIndex) {
        slotsRepository.add(personaIndex);
    }

    public void onPersonaDeleted(short personaIndex) {
        slotsRepository.delete(personaIndex);
    }

    public void onPersonaAuthenticated(short personaIndex, short score) {
        if (!slotsRepository.exists(personaIndex)) {
            slotsRepository.add(personaIndex);
        }
        slotsRepository.openSlot(personaIndex);
    }

    protected void processSelect() {
        if (!selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        Slot slot = slotsRepository.getOpenedSlot();

        short length = Util.setShort(buffer, Utils.SHORT_00, slot == null ? NO_OPEN_SLOT : slot.getId());
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    protected void processInternal(APDU apdu) throws ISOException {
        switch (this.ins) {
            case INS_ENCRYPT:
                checkClaIsInterindustry();
                processEncrypt();
                break;
            case INS_DECRYPT:
                checkClaIsInterindustry();
                processDecrypt();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processDecrypt() {
        if (p1 != P1_DECRYPT || p2 != P2_DECRYPT) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        Slot openedSlot = slotsRepository.getOpenedSlot();

        if (openedSlot == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short length = openedSlot.decrypt(buffer, Utils.SHORT_00, buffer, Utils.SHORT_00, lc);

        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

    private void processEncrypt() {
        if (p1 != P1_ENCRYPT || p2 != P2_ENCRYPT) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        Slot openedSlot = slotsRepository.getOpenedSlot();

        if (openedSlot == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short length = openedSlot.encrypt(buffer, Utils.SHORT_00, buffer, Utils.SHORT_00, lc);

        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, length);
    }

}
