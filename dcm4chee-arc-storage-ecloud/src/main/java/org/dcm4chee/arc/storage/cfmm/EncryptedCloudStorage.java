/*
 * *** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is part of dcm4che, an implementation of DICOM(TM) in
 * Java(TM), hosted at https://github.com/dcm4che.
 *
 * The Initial Developer of the Original Code is
 * J4Care.
 * Portions created by the Initial Developer are Copyright (C) 2015
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * See @authors listed below
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * *** END LICENSE BLOCK *****
 */

package org.dcm4chee.arc.storage.cfmm;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.Nonnull;
import org.dcm4che3.net.Device;
import org.dcm4chee.arc.conf.StorageDescriptor;
import org.dcm4chee.arc.metrics.MetricsService;
import org.dcm4chee.arc.storage.ReadContext;
import org.dcm4chee.arc.storage.UploadTaskWriteContext;
import org.dcm4chee.arc.storage.WriteContext;
import org.dcm4chee.arc.storage.cloud.CloudStorage;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.io.Payload;
import org.jclouds.io.payloads.InputStreamPayload;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.KeyStore;
import java.time.Instant;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import javax.crypto.Mac;

/**
 * @author Martyn Klassen<lmklassen@gmail.com>
 * @since Jan 2026
 * Header format:
 * MAGIC (4 bytes) | VERSION (1 byte) | ALG_AES256_GCM (1 byte) | IV Length (2 bytes) | IV (12 bytes) | Commitment (32 bytes)
 */
public class EncryptedCloudStorage extends CloudStorage {

    private static final Logger LOG = LoggerFactory.getLogger(EncryptedCloudStorage.class);

    private static final String DEFAULT_CONTAINER = "org.dcm4chee.arc";

    private static final SecureRandom SR = new SecureRandom();

    // Header constants
    private static final int MAGIC = 0xC1533301; // "C S 3 1"
    private static final byte VERSION = 1;
    private static final byte ALG_AES256_GCM = 0x11;
    private static final int GCM_TAG_LEN_BITS = 128; // 16 bytes

    private final String container;
    private final BlobStoreContext context;
    private final String edkSuffix;
    private final String edkPrefix;

    private final KeyWrapProvider keyWrapProvider;   // AES-KW / KMS / RSA

    private boolean createBucket;

    protected EncryptedCloudStorage(StorageDescriptor descriptor, MetricsService metricsService, Device device) {
        super(descriptor, metricsService, device);
        container = descriptor.getProperty("encryption.container", DEFAULT_CONTAINER);
        createBucket = !(Boolean.parseBoolean(descriptor.getProperty("encryption.containerExists", null)));
        // Parse the scheme and endpoint
        String api = descriptor.getProperty("encryption.uri", null);
        String endpoint = null;
        int endApi = api.indexOf(':');
        if (endApi != -1) {
            endpoint = api.substring(endApi + 1);
            api = api.substring(0, endApi);
        }
        ContextBuilder ctxBuilder = ContextBuilder.newBuilder(api);
        String identity = descriptor.getProperty("encryption.identity", null);
        if (identity != null)
            ctxBuilder.credentials(identity, descriptor.getProperty("encryption.credential", null));
        if (endpoint != null)
            ctxBuilder.endpoint(endpoint);
        Properties overrides = new Properties();
        for (Map.Entry<String, String> entry : descriptor.getProperties().entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("encryption.jclouds."))
                overrides.setProperty(key, entry.getValue());
        }
        ctxBuilder.overrides(overrides);
        ctxBuilder.modules(Collections.singleton(new SLF4JLoggingModule()));
        context = ctxBuilder.buildView(BlobStoreContext.class);

        // Suffix and prefix for EDK sidecar appended to the data object storage path
        this.edkSuffix = descriptor.getProperty("encryption.suffix", ".edk");
        this.edkPrefix = descriptor.getProperty("encryption.prefix", "");

        // Password for keystore and keystore entries.
        // Unique per entry passwords are not supported.
        String passwordProperty = descriptor.getProperty("encryption.keystore.passwordProperty",
                "encryption-keystore-password");
        String entryPasswordProperty = descriptor.getProperty("encryption.keystore.entryPasswordProperty",
                "encryption-keystore-entry-password");

        String ksPassValue = System.getProperty(passwordProperty, null);
        if (ksPassValue == null) {
            throw new IllegalArgumentException("Missing Java property " + passwordProperty + " required for encryption keystore");
        }
        char[] ksPass = ksPassValue.toCharArray();

        String entryPassVal = System.getProperty(entryPasswordProperty, ksPassValue);
        char[] ksEntryPass = (entryPassVal != null && !entryPassVal.isEmpty()) ? entryPassVal.toCharArray() : ksPass;

        // Initialize the keystore provider.
        try {
            // Load the keystore
            KeyStore ks = KeyStoreKeyWrapProvider.loadKeyStore(
                    descriptor.getProperty("encryption.keystore.type", "PKCS12"),
                    descriptor.getProperty("encryption.keystore.path", null),
                    ksPass,
                    null);

            // Use the keystore as the provider for wrapping data encryption keys
            // The keyAlias is the default key that will be used for all wrap operations
            this.keyWrapProvider = new KeyStoreKeyWrapProvider(
                    ks,
                    ksEntryPass,
                    descriptor.getProperty("encryption.keyAlias", null)
                    );
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Failed to load encryption keystore", e);
        }
    }

    @Override
    protected Logger log() {
        return LOG;
    }

    @Override
    protected OutputStream openOutputStreamA(final WriteContext ctx) throws IOException {
        // Check for the EDK sidecar bucket
        ensureBucketExists();

        // Initialize the unencrypted stream
        OutputStream os = super.openOutputStreamA(ctx);

        // There is no reliable way to determine if the os is a Null output stream.
        // No encryption should be performed for a null output stream.
        // Resort to checking if an upload task is present.
        if (((UploadTaskWriteContext) ctx).getUploadTask() == null)
            return os;

        // Remove any existing sidecar for the item, for example, an orphaned sidecar from a previous upload.
        ensureStoragePathNotExists(ctx);

        // Initialize encryption
        EncryptionContext eCtx = new EncryptionContext(keyWrapProvider);

        // If the length is set, then add the header and GCM tag lengths
        long length = ctx.getContentLength();
        if (length >= 0) {
            // Add the header size and GCM tag size to the content length
            length += HeaderV1.HEADER_LEN + GCM_TAG_LEN_BITS / 8;
            ctx.setContentLength(length);
        }

        // Write the sidecar for the file. The sidecar is written before the data is uploaded. It will be removed when
        // the upload fails. However, orphaned sidecars may remain if the upload is interrupted, for example, a server
        // crashes after the sidecar is written but before the upload completes.
        // Writing the sidecar after the upload completes is problematic because the user may try to download the newly
        // uploaded file before the sidecar has been written. We also do not want to waste resources uploading a large
        // object only to have the sidecar generation fail.
        writeEdkSidecar(ctx, eCtx);

        // Wrap the stream for encryption
        os = new EncryptingOutputStream(os, eCtx);

        // The encryption context has been consumed. Zero out the header fields immediately.
        eCtx.zero();

        return os;
    }

    @Override
    protected void copyA(InputStream in, WriteContext ctx) throws IOException {
        // Need to open a new encrypted stream and transfer the input to the new stream
        try (OutputStream os = openOutputStreamA(ctx)) {
            in.transferTo(os);
        }
    }

    @Override
    protected void afterOutputStreamClosed(WriteContext ctx) throws IOException {
        try {
            // Rely on the superclass to throw an IOException if the upload fails.
            // It is possible to call get() on the FurtureTask ourselves to check for underlying errors,
            // but current the superclass throws IOException for all errors.
            super.afterOutputStreamClosed(ctx);
        } catch (IOException e) {
            // Remove the EDK sidecar the upload operation fails
            removeEdkSidecarIfExists(ctx);
            throw e;
        }
    }

    private void ensureBucketExists() {
        // Try to create the bucket if it does not exist.
        if (!createBucket)
            return;
        BlobStore blobStore = context.getBlobStore();
        if (!blobStore.containerExists(container)) {
            blobStore.createContainerInLocation(null, container);
        }
        createBucket = false;
    }

    private void ensureStoragePathNotExists(WriteContext ctx) {
        BlobStore blobStore = context.getBlobStore();
        String storagePath = edkPathFor(ctx.getStoragePath());
        if (blobStore.blobExists(container, storagePath)) {
            switch (descriptor.getOnStoragePathAlreadyExists()) {
                case NOOP:
                case FAILURE:
                    // The EDK is expected to exist if the data object exists.
                    return;
                default:
                    // The object does not exist, but the corresponding EDK does.
                    // The EDK is therefore stale and should be removed.
                    blobStore.removeBlob(container, storagePath);
            }
        }
    }


    @Override
    protected InputStream openInputStreamA(ReadContext ctx) throws IOException {
        // Get the undecrypted stream from super class
        InputStream raw = super.openInputStreamA(ctx);

        // 1) Read and verify header, capture header bytes for AAD
        HeaderV1 header;
        try {
            header = HeaderV1.readFrom(raw);
        } catch (IOException e) {
            raw.close();
            throw e;
        }

        // 2) Load EDK sidecar
        BlobStore blobStore = context.getBlobStore();
        String storagePath = edkPathFor(ctx.getStoragePath());
        Blob blob = blobStore.getBlob(container, storagePath);
        if (blob == null) {
            raw.close();
            throw new IOException("Missing EDK sidecar: container=" + container + " path=" + storagePath);
        }

        try {
            EdkRecord edk;
            try (InputStream blobIn = blob.getPayload().openStream()) {
                edk = EdkRecord.fromJson(blobIn);
            }

            // 3) Unwrap DEK
            byte[] dek = keyWrapProvider.unwrap(edk.wrapAlias, edk.edk);
            // Remove the EDK from memory immediately.
            Arrays.fill(edk.edk, (byte) 0);

            // 4) Verify commitment before streaming decrypt
            if (!header.verifyCommitment(dek)) {
                raw.close();
                throw new SecurityException("DEK commitment mismatch (wrong KEK or tampered sidecar)");
            }
            // 5) Setup cipher and stream-decrypt the remainder (ciphertext||tag)
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN_BITS, header.iv);
            SecretKey aesKey = new SecretKeySpec(dek, "AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            cipher.updateAAD(header.rawBytes()); // bind to header
            // Immediately zero the decrypted DEK once it is no longer required.
            Arrays.fill(dek, (byte) 0);
            return new CipherInputStream(raw, cipher);
        } catch (IOException e) {
            raw.close();
            throw e;
        } catch (GeneralSecurityException e) {
            raw.close();
            throw new IOException("Failed to init decryption", e);
        }
    }

    @Override
    protected boolean existsA(ReadContext ctx) {
        // Make sure the EDK sidecar exists before checking the data object.
        BlobStore blobStore = context.getBlobStore();
        String storagePath = edkPathFor(ctx.getStoragePath());
        if (!blobStore.blobExists(container, storagePath)) {
            return false;
        }
        // Let super class check the data object.
        return super.existsA(ctx);
    }

    @Override
    protected void deleteObjectA(String storagePath) throws IOException {
        // Remove the EDK sidecar before deleting the data object.
        BlobStore blobStore = context.getBlobStore();
        String storagePathBlob = edkPathFor(storagePath);
        if (blobStore.blobExists(container, storagePathBlob)) {
            blobStore.removeBlob(container, storagePathBlob);
        }
        // Let super class delete the data object.
        super.deleteObjectA(storagePath);
    }

    @Override
    public void close() throws IOException {
        // Close the super class
        super.close();

        // Close the blob store context for the EDK sidecar bucket.
        context.close();
    }

    private String edkPathFor(String dataPath) {
        return edkPrefix + dataPath + edkSuffix;
    }

    private void removeEdkSidecarIfExists(WriteContext ctx) {
        // Delete the EDK sidecar if it exists.
        BlobStore blobStore = context.getBlobStore();
        String storagePath = edkPathFor(ctx.getStoragePath());
        if (blobStore.blobExists(container, storagePath)) {
            blobStore.removeBlob(container, storagePath);
        }
    }

    /**
     * Writes encryption metadata as JSON sidecar blob
     */
    private void writeEdkSidecar(WriteContext ctx, EncryptionContext eCtx) throws IOException {
        BlobStore blobStore = context.getBlobStore();
        ObjectMapper om = new ObjectMapper();
        ObjectNode node = om.createObjectNode();
        node.put("wrapAlias", eCtx.wrapAlias);
        node.put("createdAt", Instant.now().toString());
        node.put("edk", Base64.getEncoder().encodeToString(eCtx.edk));
        byte[] edkJson = om.writeValueAsBytes(node);

        Payload payload = new InputStreamPayload(new ByteArrayInputStream(edkJson));
        payload.getContentMetadata().setContentLength((long) edkJson.length);
        Blob blob = blobStore.blobBuilder(edkPathFor(ctx.getStoragePath())).payload(payload)
                .contentType("application/json").build();
        blobStore.putBlob(container, blob);
    }

    private static byte[] secureRandom(int n) {
        byte[] b = new byte[n];
        SR.nextBytes(b);
        return b;
    }

    // --- EncryptingOutputStream: writes header then AES-GCM stream -----------
    private static class EncryptingOutputStream extends OutputStream {
        private final OutputStream dest;
        private final CipherOutputStream cos;
        private boolean closed = false;

        EncryptingOutputStream(OutputStream dest, EncryptionContext ctx) throws IOException {
            this.dest = dest;
            try {
                // Initialize cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN_BITS, ctx.header.iv);
                SecretKey aesKey = new SecretKeySpec(ctx.dek, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
                cipher.updateAAD(ctx.header.rawBytes());
                // Write header immediately (binds AAD before any ciphertext)
                dest.write(ctx.header.rawBytes());
                this.cos = new CipherOutputStream(dest, cipher);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to init encryption", e);
            }
        }

        @Override public void write(int b) throws IOException { cos.write(b); }
        @Override public void write(@Nonnull byte[] b, int off, int len) throws IOException { cos.write(b, off, len); }
        @Override public void flush() throws IOException { cos.flush(); }
        @Override public void close() throws IOException {
            if (closed) return;
            try {
                cos.close(); // emits GCM tag
            } finally {
                dest.close();
                closed = true;
            }
        }
    }

    // --- Per-write context (holds DEK/header/EDK) ----------------------------
    private static class EncryptionContext {
        byte[] dek;
        byte[] edk;
        HeaderV1 header;
        String wrapAlias;

        EncryptionContext(KeyWrapProvider keyWrapProvider) throws IOException {
            try {
                // Create a new 256-bit data encryption key (DEK)
                dek = secureRandom(32);

                // Build header (without commitment), then compute commitment and freeze raw bytes
                HeaderV1 header = HeaderV1.create(secureRandom(12));
                header.computeAndAttachCommitment(dek);

                // Get the alias used for wrapping the DEK
                wrapAlias = keyWrapProvider.wrapAlias();

                // Pre-wrap DEK for storage in EDK sidecar
                edk = keyWrapProvider.wrap(dek);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to prepare encryption", e);
            }
        }

        void zero() {
            if (dek != null) Arrays.fill(dek, (byte) 0);
            if (edk != null) Arrays.fill(edk, (byte) 0);
            // The EDK and header by design do not have sensitive information and are publicly available,
            // so they are not zeroed.
        }
    }

    // --- EDK record ----------------------------------------------------------
    private record EdkRecord(String wrapAlias, byte[] edk) {

        static EdkRecord fromJson(InputStream in) throws IOException {
            ObjectMapper om = new ObjectMapper();
            ObjectNode n = (ObjectNode) om.readTree(in);
            JsonNode aliasNode = n.get("wrapAlias");
            JsonNode edkNode = n.get("edk");
            if (aliasNode == null || edkNode == null)
                throw new IOException("EDK sidecar missing wrapAlias or edk fields");
            String wrapAlias = aliasNode.asText();
            byte[] edk = Base64.getDecoder().decode(edkNode.asText());
            return new EdkRecord(wrapAlias, edk);
        }
    }

    // --- HeaderV1 codec ------------------------------------------------------
    private static class HeaderV1 {
        // The header does not contain any information about the DEK or EDK. The association of an EDK with a data
        // object and vice versa must be stored separately. This is to avoid needing to read the header before deleting
        // an object to also delete the EDK sidecar.
        final byte[] iv;         // 12 bytes
        private byte[] raw;      // serialized header (incl. commitment)
        private byte[] commitment;

        static final int HEADER_LEN = 4 + 1 + 1 + 2 + 12 + 32;

        private HeaderV1(byte[] iv) {
            this.iv = iv;
        }

        private HeaderV1(byte[] iv, byte[] commitment, byte[] raw) {
            this.iv = iv;
            this.commitment = commitment;
            this.raw = raw;
        }

        static HeaderV1 create(byte[] iv) {
            return new HeaderV1(iv);
        }

        private byte[] commitment(byte[] dek) throws GeneralSecurityException, IOException {
            byte[] headerNoCommit = serialize(false);
            byte[] commitKey = hkdfSha256(dek, "commitment".getBytes(), "v1".getBytes(), 32);
            return hmacSha256(commitKey, headerNoCommit);
        }

        void computeAndAttachCommitment(byte[] dek) throws GeneralSecurityException, IOException {
            this.commitment = commitment(dek);
            this.raw = serialize(true); // final bytes
        }

        boolean verifyCommitment(byte[] dek) throws IOException, GeneralSecurityException {
            byte[] expected = commitment(dek);
            return MessageDigest.isEqual(expected, this.commitment);
        }

        byte[] rawBytes() { return raw; }

        private byte[] serialize(boolean includeCommit) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(80);
            DataOutputStream dos = new DataOutputStream(baos);
            // Store the information about the encryption used
            dos.writeInt(MAGIC);
            dos.writeByte(VERSION);
            dos.writeByte(ALG_AES256_GCM);
            // Store the unique iv
            dos.writeShort( (short) iv.length ); // ivLen
            dos.write(iv);
            // Store the commitment (if requested)
            if (includeCommit) {
                dos.write(commitment);
            }
            dos.flush();
            return baos.toByteArray();
        }

        static HeaderV1 readFrom(InputStream in) throws IOException {
            // Read exactly HEADER_LEN bytes from raw, without extra buffering
            byte[] hdr = readExact(in, HEADER_LEN);

            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(hdr));
            int magic = dis.readInt();
            if (magic != MAGIC) throw new IOException("Bad magic");
            byte ver = dis.readByte();
            if (ver != VERSION) throw new IOException("Unsupported version " + ver);
            byte alg = dis.readByte();
            if (alg != ALG_AES256_GCM) throw new IOException("Unsupported algSuite " + alg);
            int ivLen = Short.toUnsignedInt(dis.readShort());
            if (ivLen != 12) throw new IOException("Unexpected ivLen=" + ivLen);
            byte[] iv = dis.readNBytes(ivLen);
            byte[] commit = dis.readNBytes(32);

            return new HeaderV1(iv, commit, hdr);
        }

        @SuppressWarnings("SameParameterValue")
        private static byte[] readExact(InputStream in, int len) throws IOException {
            byte[] buf = new byte[len];
            int off = 0;
            while (off < len) {
                int r = in.read(buf, off, len - off);
                if (r < 0) throw new EOFException("Unexpected EOF reading header");
                off += r;
            }
            return buf;
        }
    }

    // --- HKDF & HMAC utilities ----------------------------------------------
    @SuppressWarnings("SameParameterValue")
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len)
            throws GeneralSecurityException {
        // Using RFC5869
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        mac.init(saltKey);
        byte[] prk = mac.doFinal(ikm);

        byte[] t = new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int counter = 1;
        while (out.size() < len) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter++);
            t = mac.doFinal();
            out.write(t, 0, Math.min(t.length, len - out.size()));
        }
        return out.toByteArray();
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
