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

import org.idpass.tools.Utils;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

final class SamSlot implements Slot {
    private static final short OPENED_INDEX = 0;

    private static final short LENGTH_BYTE  = 8;

    private static final short SIZE_RAM     = 32;

    private static final short LENGTH_BLOCK = (short) (128 / LENGTH_BYTE);

    private AESKey             keyEnc;
    private DESKey             keyMac;
    private Cipher             cipher;
    private Signature          signature;
    private RandomData         random;
    private byte[]             ram;

    private boolean[]          opened;
    private short              id;

    SamSlot(short id, RandomData random, Cipher cipher, Signature signature) {
        this.id = id;
        this.random = random;
        this.cipher = cipher;
        this.signature = signature;

        ram = JCSystem.makeTransientByteArray(SIZE_RAM, JCSystem.CLEAR_ON_RESET);

        keyEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        random.generateData(ram, (short) 0, (short) (keyEnc.getSize() / LENGTH_BYTE));
        keyEnc.setKey(ram, (short) 0);
        
        keyMac = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);        
        random.generateData(ram, (short) 0, (short) (keyMac.getSize() / LENGTH_BYTE));
        keyMac.setKey(ram, (short) 0);
        
        opened = JCSystem.makeTransientBooleanArray((short) (OPENED_INDEX + 1), JCSystem.CLEAR_ON_RESET);

    }

    public short getId() {
        return id;
    }

    public void open() {
        opened[OPENED_INDEX] = true;
    }

    public void close() {
        opened[OPENED_INDEX] = false;
    }

    public boolean isOpened() {
        return opened[OPENED_INDEX];
    }

    public short encrypt(byte[] inBuf, short inOff, byte[] outBuf, short outOff, short inLen) {

        if (!this.isOpened()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        random.generateData(ram, Utils.SHORT_00, LENGTH_BLOCK);
        Util.arrayCopy(inBuf, inOff, outBuf, (short) (outOff + LENGTH_BLOCK), inLen);
        Util.arrayCopy(ram, Utils.SHORT_00, outBuf, outOff, LENGTH_BLOCK);

        cipher.init(keyEnc, Cipher.MODE_ENCRYPT);
        short encLength = cipher.doFinal(outBuf, outOff, (short) (inLen + LENGTH_BLOCK), outBuf, outOff);

        signature.init(keyMac, Signature.MODE_SIGN);
        short signatureLength = signature.sign(outBuf, outOff, encLength, outBuf, (short) (outOff + encLength));
        return (short) (encLength + signatureLength);
    }

    public short decrypt(byte[] inBuf, short inOff, byte[] outBuf, short outOff, short inLen) {

        if (!this.isOpened()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        signature.init(keyMac, Signature.MODE_VERIFY);

        short signatureLength = signature.getLength();

        if (!signature.verify(inBuf, inOff, (short) (inLen - signatureLength), inBuf,
                              (short) (inLen - signatureLength), signatureLength)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        cipher.init(keyEnc, Cipher.MODE_DECRYPT);

        short length = cipher.doFinal(inBuf, inOff, (short) (inLen - signatureLength), outBuf, outOff);

        short offset =
                       Util.arrayCopy(outBuf, (short) (outOff + LENGTH_BLOCK), outBuf, outOff,
                                      (short) (length - LENGTH_BLOCK));

        return (short) (offset - outOff);
    }
}
