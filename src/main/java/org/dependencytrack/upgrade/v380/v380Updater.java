/*
 * This file is part of Dependency-Track.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v380;

import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import java.sql.Connection;

public class v380Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v380Updater.class);
    private static final String STMT_1 = "UPDATE \"REPOSITORY\" SET \"URL\" = 'https://repo1.maven.org/maven2/' WHERE \"TYPE\" = 'MAVEN' AND \"IDENTIFIER\" = 'central'";

    @Override
    public String getSchemaVersion() {
        return "3.8.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager alpineQueryManager, final Connection connection) throws Exception {
        LOGGER.info("Updating Maven Central URL");
        DbUtil.executeUpdate(connection, STMT_1);

    }
}