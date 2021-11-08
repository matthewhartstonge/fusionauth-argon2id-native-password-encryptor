/*
 * Copyright (c) 2021. Matthew Hartstonge <matt@mykro.co.nz>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nz.mykro.fusionauth.plugins;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import io.fusionauth.plugin.spi.security.PasswordEncryptor;


import java.nio.charset.StandardCharsets;
import java.util.Base64;


/**
 * Argon2idNativePasswordEncryptor provides a plugin for generating argon2id
 * based digests for passwords using Java Native Access (`jna`) which under the
 * hood calls out to the natively compiled reference C implementation of
 * Argon2id.
 *
 * @author Matthew Hartstonge
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9106#section-4"> RFC9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications </a>
 * @see <a href="https://github.com/phxql/argon2-jvm"> Argon2-jvm Github Repo </a>
 * @see <a href="https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf"> Original Argon2 Whitepaper </a>
 */
public class Argon2idNativePasswordEncryptor implements PasswordEncryptor {
    private final Argon2Advanced argon2;

    /**
     * If much less memory is available, a uniformly safe option is
     * Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
     * RAM), 128-bit salt, and 256-bit tag size.  This is the SECOND
     * RECOMMENDED option.
     * <p>
     * Refer: https://datatracker.ietf.org/doc/html/rfc9106#section-4
     */
    private static final Argon2Factory.Argon2Types DEFAULT_TYPE = Argon2Factory.Argon2Types.ARGON2id;
    private static final int DEFAULT_TIME_COST = 3;         // t=3           (3 Iterations)
    private static final int DEFAULT_MEMORY_COST = 1 << 16; // m=2^16        (64MiB Memory)
    private static final int DEFAULT_PARALLELISM = 4;       // p=4           (4 Lanes)
    private static final int DEFAULT_TAG_SIZE = 1 << 8;     // tag size=2^8  (256-bit hash size)
    private static final int DEFAULT_SALT_SIZE = 1 << 7;    // salt size=2^7 (128-bit salt size)

    // Argon2idNativePasswordEncryptor configures the internal argon2 config.
    public Argon2idNativePasswordEncryptor() {
        int hashLengthBytes = DEFAULT_TAG_SIZE / 8;
        int saltLengthBytes = DEFAULT_SALT_SIZE / 8;
        this.argon2 = Argon2Factory.createAdvanced(DEFAULT_TYPE, saltLengthBytes, hashLengthBytes);
    }

    @Override
    public int defaultFactor() {
        return DEFAULT_TIME_COST;
    }

    @Override
    public String encrypt(String password, String salt, int factor) {
        if (factor <= 0) {
            throw new IllegalArgumentException("Invalid factor value [" + factor + "]");
        }

        String hash = this.argon2.hash(
                factor,
                DEFAULT_MEMORY_COST,
                DEFAULT_PARALLELISM,
                password.toCharArray(),
                StandardCharsets.UTF_8,
                Base64.getDecoder().decode(salt)
        );

        return new String(hash.getBytes());
    }
}
