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

import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import org.idpass.tools.Utils;

/**
 * Slots Repository class
 * 
 * @author m.samarskiy
 *
 */
final class SlotsRepository {
    
    private Cipher             cipher;
    private Signature          signature;
    private RandomData         random;

    /**
     * Factory method
     * 
     * @return SlotsRepository instance
     */
    static SlotsRepository create() {
        return new SlotsRepository();
    }

    private Slot[] slots;

    /**
     * Get all slots
     * 
     * @return slots array
     */
    Slot[] getItems() {
        return slots;
    }

    
    /**
     * Check if slot exists 
     * 
     * @param index slot index
     * @return true if slot exists
     */
    boolean exists(short index) {
        return !(slots.length <= index || slots[index] == null);
    }

    /**
     * Add new slot
     * 
     * @param newIndex new slot index
     */
    void add(short newIndex) {
        boolean foundNewItem = newIndex < slots.length;

        if (!foundNewItem) {
            short extendCount = (short) (newIndex - slots.length + 1);
            extendArray(extendCount);
        }

        Slot newSlot = new SamSlot(newIndex, random, cipher, signature);
        slots[newIndex] = newSlot;

        Utils.requestObjectDeletion();
    }

    /**
     * Reset all slots
     */
    void reset() {
        slots = new Slot[0];
        Utils.requestObjectDeletion();
    }

    
    /**
     * Open slot
     * 
     * @param id slot id
     */
    void openSlot(short id) {
        if (slots.length <= id)
            return;

        for (short i = 0; i < slots.length; i++) {
            if (slots[i] == null) continue;
            
            if (i == id) {
                slots[i].open();
            } else {
                slots[i].close();
            }
        }
    }

    /**
     * Get curent opened slot
     * @return current opened slot
     */
    Slot getOpenedSlot() {
        for (short i = 0; i < slots.length; i++) {
            if (slots[i] == null) continue;
            if (slots[i].isOpened()) {
                return slots[i];
            }
        }
        return null;
    }

    /**
     * Delete slot
     * @param index slot index
     * @return true if deleted
     */
    boolean delete(short index) {
        if (slots.length <= index)
            return false;

        if (slots[index] == null) {
            return true;
        }

        slots[index] = null;
        Utils.requestObjectDeletion();
        return true;
    }

    private void extendArray(short extendCount) {
        Slot[] arr = new Slot[(short) (slots.length + extendCount)];

        for (short i = 0; i < slots.length; i++) {
            arr[i] = slots[i];
        }

        slots = arr;
        Utils.requestObjectDeletion();
    }

    private SlotsRepository() {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        signature = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
        
        this.slots = new Slot[0];
    }

}
