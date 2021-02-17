/**
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.remoteprovisioner;

import android.annotation.NonNull;
import android.os.RemoteException;
import android.security.remoteprovisioning.IRemoteProvisioning;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Provides an easy package to run the provisioning process from start to finish, interfacing
 * with the remote provisioning system service and the server backend in order to provision
 * attestation certificates to the device.
 */
public class Provisioner {
    private static final String PROVISIONING_URL = "";
    private static final String GEEK_URL = PROVISIONING_URL + "/v1/eekchain";
    private static final String CERTIFICATE_SIGNING_URL =
            PROVISIONING_URL + "/v1:signCertificates?challenge=";
    private static final String TAG = "RemoteProvisioningService";

    private static final byte ECDSA_UNCOMPRESSED_BYTE = 0x04;

    /**
     * Takes a byte array composed of DER encoded certificates and returns the X.509 certificates
     * contained within as an X509Certificate array.
     */
    private static X509Certificate[] formatX509Certs(byte[] certStream)
            throws CertificateException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(certStream);
        ArrayList<Certificate> certs = new ArrayList<Certificate>(fact.generateCertificates(in));
        return certs.toArray(new X509Certificate[certs.size()]);
    }

    /**
     * Calls out to the specified backend servers to retrieve an Endpoint Encryption Key and
     * corresponding certificate chain to provide to KeyMint. This public key will be used to
     * perform an ECDH computation, using the shared secret to encrypt privacy sensitive components
     * in the bundle that the server needs from the device in order to provision certificates.
     *
     * A challenge is also returned from the server so that it can check freshness of the follow-up
     * request to get keys signed.
     */
    private static GeekResponse fetchGeek() {
        try {
            URL url = new URL(GEEK_URL);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Server connection for GEEK failed, response code: "
                        + con.getResponseCode());
            }

            BufferedInputStream inputStream = new BufferedInputStream(con.getInputStream());
            ByteArrayOutputStream cborBytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read = 0;
            while ((read = inputStream.read(buffer, 0, buffer.length)) != -1) {
                cborBytes.write(buffer, 0, read);
            }
            inputStream.close();
            return CborUtils.parseGeekResponse(cborBytes.toByteArray());
        } catch (IOException e) {
            Log.e(TAG, "Failed to fetch GEEK from the servers.", e);
            return null;
        }
    }

    /**
     * Ferries the CBOR blobs returned by KeyMint to the provisioning server. The data sent to the
     * provisioning server contains the MAC'ed CSRs and encrypted bundle containing the MAC key and
     * the hardware unique public key.
     *
     * @param cborBlob The CBOR encoded data containing the relevant pieces needed for the server to
     *                    sign the CSRs. The data encoded within comes from Keystore / KeyMint.
     *
     * @param challenge The challenge that was sent from the server. It is included here even though
     *                    it is also included in `cborBlob` in order to allow the server to more
     *                    easily reject bad requests.
     *
     * @return A List of byte arrays, where each array contains an entire PEM-encoded certificate
     *                    for one attestation key pair.
     */
    private static List<byte[]> requestSignedCertificates(byte[] cborBlob, byte[] challenge) {
        try {
            URL url = new URL(CERTIFICATE_SIGNING_URL + new String(challenge, "UTF-8"));
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                Log.e(TAG, "Server connection for signing failed, response code: "
                        + con.getResponseCode());
            }
            // May not be able to use try-with-resources here if the connection gets closed due to
            // the output stream being automatically closed.
            try (OutputStream os = con.getOutputStream()) {
                os.write(cborBlob, 0, cborBlob.length);
            } catch (Exception e) {
                return null;
            }

            BufferedInputStream inputStream = new BufferedInputStream(con.getInputStream());
            ByteArrayOutputStream cborBytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read = 0;
            while ((read = inputStream.read(buffer, 0, buffer.length)) != -1) {
                cborBytes.write(buffer, 0, read);
            }
            return CborUtils.parseSignedCertificates(cborBytes.toByteArray());
        } catch (IOException e) {
            Log.w(TAG, "Failed to request signed certificates from the server", e);
            return null;
        }
    }

    /**
     * Drives the process of provisioning certs. The method first contacts the provided backend
     * server to retrieve an Endpoing Encryption Key with an accompanying certificate chain and a
     * challenge. It passes this data and the requested number of keys to the remote provisioning
     * system backend, which then works with KeyMint in order to get a CSR bundle generated, along
     * with an encrypted package containing metadata that the server needs in order to make
     * decisions about provisioning.
     *
     * This method then passes that bundle back out to the server backend, waits for the response,
     * and, if successful, passes the certificate chains back to the remote provisioning service to
     * be stored and later assigned to apps requesting a key attestation.
     *
     * @param numKeys The number of keys to be signed. The service will do a best-effort to
     *                     provision the number requested, but if the number requested is larger
     *                     than the number of unsigned attestation key pairs available, it will
     *                     only sign the number that is available at time of calling.
     *
     * @param secLevel Which KM instance should be used to provision certs.
     * @param binder The IRemoteProvisioning binder interface needed by the method to handle talking
     *                     to the remote provisioning system component.
     *
     * @return True if certificates were successfully provisioned for the signing keys.
     */
    public static boolean provisionCerts(int numKeys, int secLevel,
            @NonNull IRemoteProvisioning binder) {
        if (numKeys < 1) {
            Log.e(TAG, "Request at least 1 key to be signed. Num requested: " + numKeys);
            return false;
        }
        GeekResponse geek = fetchGeek();
        if (geek == null) {
            Log.e(TAG, "The geek is null");
            return false;
        }
        byte[] payload = null;
        try {
            payload = binder.generateCsr(false /* testMode */,
                    numKeys,
                    geek.geek,
                    geek.challenge,
                    secLevel);
        } catch (RemoteException e) {
            Log.e(TAG, "Failed to generate CSR blob", e);
            return false;
        }
        if (payload == null) {
            Log.e(TAG, "Keystore failed to generate a payload");
            return false;
        }
        ArrayList<byte[]> certChains =
                new ArrayList<byte[]>(requestSignedCertificates(payload, geek.challenge));
        for (byte[] certChain : certChains) {
            // DER encoding specifies leaf to root ordering. Pull the public key and expiration
            // date from the leaf.
            X509Certificate cert;
            try {
                cert = formatX509Certs(certChain)[0];
            } catch (CertificateException e) {
                Log.e(TAG, "Failed to interpret DER encoded certificate chain", e);
                return false;
            }
            // getTime returns the time in *milliseconds* since the epoch.
            long expirationDate = cert.getNotAfter().getTime();
            ECPublicKey key = (ECPublicKey) cert.getPublicKey();

            // Remote key provisioning internally supports the default, uncompressed public key
            // format for ECDSA. This defines the format as (s | x | y), where s is the byte
            // indicating if the key is compressed or not, and x and y make up the EC point.
            // However, the key as stored in a COSE_Key object is just the two points. As such,
            // the raw public key is stored in the database is (x | y), so the compression byte
            // should be dropped here.
            //
            // s: 1 byte, x: 32 bytes, y: 32 bytes
            byte[] keyEncoding = key.getEncoded();
            if (keyEncoding.length != 65) {
                Log.e(TAG, "Key is not encoded as expected, or corrupted. Length: "
                        + keyEncoding.length);
                return false;
            } else if (keyEncoding[0] != ECDSA_UNCOMPRESSED_BYTE) {
                Log.e(TAG, "Key is not uncompressed.");
            }
            byte[] rawPublicKey = Arrays.copyOfRange(keyEncoding, 1 /* from */, 65 /* to */);
            try {
                binder.provisionCertChain(rawPublicKey, certChain, expirationDate, secLevel);
            } catch (RemoteException e) {
                Log.e(TAG, "Error on the binder side when attempting to provision the signed chain",
                        e);
                return false;
            }
        }
        return true;
    }
}
