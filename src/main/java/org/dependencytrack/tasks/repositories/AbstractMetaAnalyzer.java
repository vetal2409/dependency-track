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
package org.dependencytrack.tasks.repositories;

import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;

import javax.json.Json;
import javax.json.JsonObject;
import java.util.Date;

/**
 * Base abstract class that all IMetaAnalyzer implementations should likely extend.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public abstract class AbstractMetaAnalyzer implements IMetaAnalyzer {

    String baseUrl;

    private final Logger LOGGER = Logger.getLogger(this.getClass()); // We dont want this class reporting the logger

    /**
     * {@inheritDoc}
     */
    public void setRepositoryBaseUrl(String baseUrl) {
        baseUrl = StringUtils.trimToNull(baseUrl);
        if (baseUrl == null) {
            return;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        this.baseUrl = baseUrl;
    }

    public void handleUnexpectedHttpResponse(final Logger logger, String url, final int statusCode, final String statusText, final Component component) {
        logger.debug("HTTP Status : " + statusCode + " " + statusText);
        logger.debug(" - RepositoryType URL : " + url);
        logger.debug(" - Package URL : " + component.getPurl().canonicalize());
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.REPOSITORY)
                .title(NotificationConstants.Title.REPO_ERROR)
                .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. URL: " + url + " HTTP Status: " + statusCode + ". Check log for details." )
                .level(NotificationLevel.ERROR)
        );
    }

    public void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.REPOSITORY)
                .title(NotificationConstants.Title.REPO_ERROR)
                .content("An error occurred while communicating with an " + supportedRepositoryType().name() + " repository. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }

    protected String getCurrentCache(RepositoryType source, String targetHost, String target) {
        try (QueryManager qm = new QueryManager()) {
            ComponentAnalysisCache cac = qm.getComponentAnalysisCache(ComponentAnalysisCache.CacheType.REPOSITORY, targetHost, source.name(), target);
            if (cac != null) {
                final Date now = new Date();
                final long ttl = 86400000; // TODO: Default to 24 hours. Make this configurable in a future release

                if (cac.getLastOccurrence().getTime() + ttl - now.getTime() < 0) {
                    return null;
                }

                return cac.getResult().getString("latestVersion");
            }

            LOGGER.debug("Cache record is missing for: source: " + source + " / targetHost: " + targetHost + " / target: " + target);

            return null;
        }
    }

    protected synchronized void setCache(RepositoryType source, String targetHost, String target, String result) {
        try (QueryManager qm = new QueryManager()) {
            final JsonObject resultJson = Json.createObjectBuilder().add("latestVersion", result).build();

            qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.REPOSITORY, targetHost, source.name(), target, new Date(), resultJson);
        }
    }

}
