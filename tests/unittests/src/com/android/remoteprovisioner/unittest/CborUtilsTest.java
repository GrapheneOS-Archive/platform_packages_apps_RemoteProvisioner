/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.remoteprovisioner.unittest;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

import android.platform.test.annotations.Presubmit;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;

import com.android.remoteprovisioner.CborUtils;
import com.android.remoteprovisioner.GeekResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;

@RunWith(AndroidJUnit4.class)
public class CborUtilsTest {

    private ByteArrayOutputStream baos;

    @Before
    public void setUp() throws Exception {
        baos = new ByteArrayOutputStream();
    }

    @Presubmit
    @Test
    public void testParseSignedCertificatesFakeData() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .add(new byte[] {0x01, 0x02, 0x03})
                .addArray()
                    .add(new byte[] {0x04, 0x05, 0x06})
                    .add(new byte[] {0x07, 0x08, 0x09})
                    .end()
                .end()
            .build());
        byte[] encodedBytes = baos.toByteArray();
        ArrayList<byte[]> certChains =
            new ArrayList<byte[]>(CborUtils.parseSignedCertificates(encodedBytes));
        assertArrayEquals(new byte[] {0x04, 0x05, 0x06, 0x01, 0x02, 0x03}, certChains.get(0));
        assertArrayEquals(new byte[] {0x07, 0x08, 0x09, 0x01, 0x02, 0x03}, certChains.get(1));
    }

    @Test
    public void testParseSignedCertificatesWrongSize() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .add(1)
                .end()
            .build());
        assertNull(CborUtils.parseSignedCertificates(baos.toByteArray()));
    }

    @Test
    public void testParseSignedCertificatesWrongTypeSharedCerts() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .add("Should be a bstr")
                .addArray()
                    .add(new byte[] {0x04, 0x05, 0x06})
                    .add(new byte[] {0x07, 0x08, 0x09})
                    .end()
                .end()
            .build());
        assertNull(CborUtils.parseSignedCertificates(baos.toByteArray()));
    }

    @Test
    public void testParseSignedCertificatesWrongTypeUniqueCerts() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .add(new byte[] {0x01, 0x02, 0x03})
                .addArray()
                    .add(new byte[] {0x04, 0x05, 0x06})
                    .add("Every entry should be a bstr")
                    .add(new byte[] {0x07, 0x08, 0x09})
                    .end()
                .end()
            .build());
        assertNull(CborUtils.parseSignedCertificates(baos.toByteArray()));
    }

    @Presubmit
    @Test
    public void testParseGeekResponseFakeData() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .addArray()                                       // GEEK Chain
                    .add(new byte[] {0x01, 0x02, 0x03})
                    .add(new byte[] {0x04, 0x05, 0x06})
                    .add(new byte[] {0x07, 0x08, 0x09})
                    .end()
                .add(new byte[] {0x0a, 0x0b, 0x0c})               // Challenge
                .end()
            .build());
        GeekResponse resp = CborUtils.parseGeekResponse(baos.toByteArray());
        baos.reset();
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .add(new byte[] {0x01, 0x02, 0x03})
                .add(new byte[] {0x04, 0x05, 0x06})
                .add(new byte[] {0x07, 0x08, 0x09})
                .end()
            .build());
        byte[] expectedGeek = baos.toByteArray();
        assertArrayEquals(expectedGeek, resp.geek);
        assertArrayEquals(new byte[] {0x0a, 0x0b, 0x0c}, resp.challenge);
    }

    @Test
    public void testParseGeekResponseWrongSize() throws Exception {
        new CborEncoder(baos).encode(new CborBuilder()
            .addArray()
                .addArray()
                    .add(new byte[] {0x01, 0x02, 0x03})
                    .add(new byte[] {0x04, 0x05, 0x06})
                    .add(new byte[] {0x07, 0x08, 0x09})
                    .end()
                .add(new byte[] {0x0a, 0x0b, 0x0c})
                .add("One more entry than there should be")
                .end()
            .build());
        assertNull(CborUtils.parseGeekResponse(baos.toByteArray()));
    }
}
