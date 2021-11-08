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

package nz.mykro.fusionauth.plugins.guice;

import com.google.inject.AbstractModule;
import com.google.inject.multibindings.MapBinder;
import io.fusionauth.plugin.spi.PluginModule;
import io.fusionauth.plugin.spi.security.PasswordEncryptor;
import nz.mykro.fusionauth.plugins.Argon2idNativePasswordEncryptor;

/**
 * Argon2idNativeFusionAuthPluginModule binds in a plugin for generating
 * argon2id based digests natively.
 *
 * @author Matthew Hartstonge
 */
@PluginModule
public class Argon2idNativeFusionAuthPluginModule extends AbstractModule {
    @Override
    protected void configure() {
        MapBinder<String, PasswordEncryptor> encryptorMapBinder = MapBinder
                .newMapBinder(binder(), String.class, PasswordEncryptor.class);

        encryptorMapBinder
                .addBinding("Salted Argon2id (native)")
                .to(Argon2idNativePasswordEncryptor.class);
    }
}
