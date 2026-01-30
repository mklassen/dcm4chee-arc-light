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

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;
import java.util.Locale;

/**
 * @author Martyn Klassen<lmklassen@gmail.com>
 * @since Jan 2026
 */
public class KeyStoreKeyWrapProvider implements KeyWrapProvider {

    private final KeyStore ks;
    private final char[] entryPassword; // for SecretKeyEntry or PrivateKeyEntry
    private final String wrapAlias;

    public KeyStoreKeyWrapProvider(KeyStore ks,
                                   char[] entryPassword,
                                   String wrapAlias) throws IllegalArgumentException, GeneralSecurityException {
        this.ks = Objects.requireNonNull(ks, "ks");
        this.entryPassword = entryPassword;
        this.wrapAlias = wrapAlias;

        // Ensure the wrap alias is in the correct format
        Cipher c = initWrapCipher(ks, entryPassword, wrapAlias);
    }

    // Helper to load a KeyStore
    public static KeyStore loadKeyStore(String type, String pathOrNull, char[] password, Provider provider) throws Exception {
        KeyStore ks = (provider != null) ? KeyStore.getInstance(type, provider) : KeyStore.getInstance(type);
        try (InputStream is = pathOrNull == null ? null : new FileInputStream(pathOrNull)) {
            ks.load(is, password);
        }
        return ks;
    }

    @Override
    public String wrapAlias()
    {
        return wrapAlias;
    }

    @Override
    public byte[] wrap(byte[] dek) throws GeneralSecurityException
    {
        return wrap(wrapAlias, dek);
    }

    private byte[] wrap(String alias, byte[] dek) throws IllegalArgumentException, GeneralSecurityException {
        Cipher c = initWrapCipher(ks, entryPassword, alias);
        SecretKey dekKey = new SecretKeySpec(dek, "AES");
        return c.wrap(dekKey);
    }

    @Override
    public byte[] unwrap(String alias, byte[] edk) throws IllegalArgumentException, GeneralSecurityException {
        Cipher c = initUnwrapCipher(ks, entryPassword, alias);
        Key key = c.unwrap(edk, "AES", Cipher.SECRET_KEY);
        return key.getEncoded();
    }

    private static Cipher initWrapCipher(KeyStore ks, char[] pwd, String alias)
            throws GeneralSecurityException {
        String wrapAlg = norm(getAlgorithm(alias));

        switch (wrapAlg) {
            case "AES256_KW": {
                KeyStore.Entry e = ks.getEntry(alias, new KeyStore.PasswordProtection(pwd));
                if (!(e instanceof KeyStore.SecretKeyEntry)) throw new KeyStoreException(alias + " is not a SecretKeyEntry");
                SecretKey kek = ((KeyStore.SecretKeyEntry) e).getSecretKey();
                Cipher c = Cipher.getInstance("AESWrap");
                c.init(Cipher.WRAP_MODE, kek); // validates provider & key usage now
                return c;
            }
            case "RSA_OAEP_3072": {
                Certificate cert = ks.getCertificate(alias);
                if (cert == null) throw new KeyStoreException("No certificate for " + alias);
                PublicKey pub = cert.getPublicKey();
                OAEPParameterSpec oaep256 = new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
                c.init(Cipher.WRAP_MODE, pub, oaep256, new SecureRandom());
                return c;
            }
            default:
                throw new NoSuchAlgorithmException("Unsupported wrapAlg: " + wrapAlg);
        }
    }

    private static Cipher initUnwrapCipher(KeyStore ks, char[] pwd, String alias)
            throws GeneralSecurityException {
        String wrapAlg = norm(getAlgorithm(alias));

        switch (wrapAlg) {
            case "AES256_KW": {
                // Expect a SecretKeyEntry holding the KEK used for AES Key Wrap
                KeyStore.Entry e = ks.getEntry(alias, new KeyStore.PasswordProtection(pwd));
                if (!(e instanceof KeyStore.SecretKeyEntry)) {
                    throw new KeyStoreException(alias + " is not a SecretKeyEntry");
                }
                SecretKey kek = ((KeyStore.SecretKeyEntry) e).getSecretKey();

                Cipher c = Cipher.getInstance("AESWrap");
                c.init(Cipher.UNWRAP_MODE, kek);  // symmetric unwrap with KEK
                return c;
            }
            case "RSA_OAEP_3072": {
                // Expect a PrivateKeyEntry for unwrapping with RSA OAEP
                KeyStore.Entry e = ks.getEntry(alias, new KeyStore.PasswordProtection(pwd));
                if (!(e instanceof KeyStore.PrivateKeyEntry)) {
                    throw new KeyStoreException(alias + " is not a PrivateKeyEntry");
                }
                PrivateKey priv = ((KeyStore.PrivateKeyEntry) e).getPrivateKey();

                OAEPParameterSpec oaep256 = new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

                // Prefer the generic OAEPPadding + parameters (widely supported on SunJCE)
                Cipher c;
                try {
                    c = Cipher.getInstance("RSA/ECB/OAEPPadding");
                    c.init(Cipher.UNWRAP_MODE, priv, oaep256, new SecureRandom());
                } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
                    // Fallback for providers that require the fully qualified name
                    c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    c.init(Cipher.UNWRAP_MODE, priv, new SecureRandom());
                }
                return c;
            }
            default:
                throw new NoSuchAlgorithmException("Unsupported wrapAlg: " + wrapAlg);
        }
    }


    private static String getAlgorithm(String alias) throws IllegalArgumentException
    {
        if (alias == null) throw new IllegalArgumentException("Null alias");
        String[] parts = alias.split(":", 3);
        String wrapAlg;
        if (parts.length == 3) {
            return norm(parts[2]);
        }
        else {
            throw new IllegalArgumentException("Invalid alias for in format name:version:algorithm: " + alias);
        }
    }

    private static String norm(String s) { return s == null ? "" : s.toUpperCase(Locale.ROOT); }
}
