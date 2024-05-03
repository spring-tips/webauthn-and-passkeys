/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A {@link Map} based implementation of {@link PublicKeyCredentialUserEntityRepository}.
 *
 * @since 6.3
 * @author Rob Winch
 */
public class MapPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

	private final Map<String, PublicKeyCredentialUserEntity> usernameToUserEntity = new HashMap<>();

	private final Map<Base64Url, String> idToUsername = new HashMap<>();

	@Override
	public String findUsernameByUserEntityId(Base64Url id) {
		Assert.notNull(id, "id cannot be null");
		return this.idToUsername.get(id);
	}

	@Override
	public PublicKeyCredentialUserEntity findByUsername(String username) {
		Assert.notNull(username, "username cannot be null");
		return this.usernameToUserEntity.get(username);
	}

	@Override
	public void save(String username, PublicKeyCredentialUserEntity userEntity) {
		Assert.notNull(username, "username cannot be null");
		if (userEntity == null) {
			PublicKeyCredentialUserEntity existing = findByUsername(username);
			if (existing != null) {
				this.usernameToUserEntity.remove(username);
				this.idToUsername.remove(existing.getId());
			}
		}
		else {
			this.usernameToUserEntity.put(username, userEntity);
			this.idToUsername.put(userEntity.getId(), username);
		}
	}

}
