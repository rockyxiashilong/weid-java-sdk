/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.util;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * test HashUtils.
 * 
 * @author v_wbjnzhang
 *
 */
public class TestHashUtils {

    private static final Logger logger = LoggerFactory.getLogger(TestHashUtils.class);

    @Test
    public void testHashUtils() {

        String rawString = "hello world.";
        byte[] rawBytes = rawString.getBytes(StandardCharsets.UTF_8);
        logger.info("Befor hash, String: {}, Bytes: {} ", 
            rawString, 
            rawBytes, 
            new String(rawBytes, StandardCharsets.UTF_8)
        );
        String hashedString = DataToolUtils.sha3(rawString);
        byte[] hashedBytes = DataToolUtils.sha3(rawBytes);
        // use assert here to verify the String to be 64 bit and Bytes[] to be
        // 32 bit
        logger.info(
            "After hash, String: {}, Bytes: {}", 
            hashedString, 
            new String(hashedBytes, StandardCharsets.UTF_8)
        );
        Assert.assertNotNull(hashedBytes);
    }
}
