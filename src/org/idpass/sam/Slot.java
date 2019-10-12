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

interface Slot {
    
    /**
     * Get slots Is
     * 
     * @return slots Id
     */
    public short getId();
    
    
    /**
     * Open slot for operations
     */
    public void open();
    
    /**
     * Close slot
     */
    public void close();
    
    /**
     * Is slot opened
     * @return true if slot opened
     */
    public boolean isOpened();
    
    /**
     * Encrypt data
     * 
     * @param inBuf data buffer to encrypt
     * @param inOff offset in data buffer
     * @param outBuf out buffer
     * @param outOff out offset 
     * @param inLen input data length
     * @return output data length
     */
    public short encrypt(byte[] inBuf, short inOff, byte[] outBuf, short outOff, short inLen);
    
    /**
     * Decrypt data
     * 
     * @param inBuf data buffer to decrypt
     * @param inOff offset in data buffer
     * @param outBuf out buffer
     * @param outOff out offset 
     * @param inLen input data length
     * @return output data length
     */
    public short decrypt(byte[] inBuf, short inOff, byte[] outBuf, short outOff, short inLen);
}
