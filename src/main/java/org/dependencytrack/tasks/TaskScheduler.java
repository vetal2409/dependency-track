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
package org.dependencytrack.tasks;

import alpine.common.util.BooleanUtil;
import alpine.event.LdapSyncEvent;
import alpine.event.framework.ChainableEvent;
import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.model.ConfigProperty;
import alpine.common.logging.Logger;
import alpine.server.tasks.AlpineTaskScheduler;
import org.dependencytrack.event.ClearComponentAnalysisCacheEvent;
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.event.DefectDojoUploadEventAbstract;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.event.KennaSecurityUploadEventAbstract;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.VulnDbSyncEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import static org.dependencytrack.model.ConfigPropertyConstants.*;

/**
 * A Singleton implementation of {@link AlpineTaskScheduler} that configures scheduled and repeatable tasks.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class TaskScheduler extends AlpineTaskScheduler {

    private static final Logger LOGGER = Logger.getLogger(TaskScheduler.class);
    // Holds an instance of TaskScheduler
    private static final TaskScheduler INSTANCE = new TaskScheduler();
    // Holds a list of all timers created during construction
    private final List<Timer> timers = new ArrayList<>();

    /**
     * Private constructor.
     */
    private TaskScheduler() {
        // Creates a new event that executes every 6 hours (21600000) after an initial 10 second (10000) delay
        scheduleEvent(new LdapSyncEvent(), 10000, 21600000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 10 second (10000) delay
        scheduleEvent(new GitHubAdvisoryMirrorEvent(), 10000, 86400000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 minute (60000) delay
        scheduleEvent(new NistMirrorEvent(), 60000, 86400000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 minute (60000) delay
        scheduleEvent(new VulnDbSyncEvent(), 60000, 86400000);

        // Creates a new event that executes every 1 hour (3600000) after an initial 10 second (10000) delay
        // TODO: uncomment this as soon as Metrics logic will be fixed, now they are useless anyway
        //  also how SindletonEvent works incorrectly, schedule of this and the following event at the same time - leads to
        //  the skip of the execution for one of them
        // scheduleEvent(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO), 10000, 3600000);

        // Creates a new event that executes every 1 hour (3600000) after an initial 10 second (10000) delay
        // TODO: uncomment this as soon as Metrics logic will be fixed, now they are useless anyway. Also there are incorrect
        //  pagination use inside 'updateVulnerabilitiesMetrics' method
        // scheduleEvent(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY), 10000, 3600000);

        // Creates a new event that executes every 24 hours (86400000) after an initial 6 hour delay
        String vulnDelay = System.getenv().getOrDefault("DEPENDENCYTRACK_VULNERABILITYANALYSIS_DELAY", "21600000");
        String vulnInterval = System.getenv().getOrDefault("DEPENDENCYTRACK_VULNERABILITYANALYSIS_INTERVAL", "86400000");
        scheduleNonParallelizedEvent(new PortfolioVulnerabilityAnalysisEvent(), Integer.parseInt(vulnDelay), Integer.parseInt(vulnInterval));

        // Creates a new event that executes every 24 hours (86400000) after an initial 1 hour (3600000) delay
        String metaDelay = System.getenv().getOrDefault("DEPENDENCYTRACK_REPOSITORYMETA_DELAY", "3600000");
        String metaInterval = System.getenv().getOrDefault("DEPENDENCYTRACK_REPOSITORYMETA_INTERVAL", "86400000");
        scheduleNonParallelizedEvent(new RepositoryMetaEvent(), Integer.parseInt(metaDelay), Integer.parseInt(metaInterval));

        // Creates a new event that executes every 6 hours (21600000) after an initial 1 hour (3600000) delay
        scheduleEvent(new InternalComponentIdentificationEvent(), 3600000, 21600000);

        // Creates a new event that executes every 72 hours (259200000) after an initial 10 second (10000) delay
        scheduleEvent(new ClearComponentAnalysisCacheEvent(), 10000, 259200000);

        // Configurable tasks
        scheduleConfigurableTask(300000, FORTIFY_SSC_ENABLED, FORTIFY_SSC_SYNC_CADENCE, new FortifySscUploadEventAbstract());
        scheduleConfigurableTask(300000, DEFECTDOJO_ENABLED, DEFECTDOJO_SYNC_CADENCE, new DefectDojoUploadEventAbstract());
        scheduleConfigurableTask(300000, KENNA_ENABLED, KENNA_SYNC_CADENCE, new KennaSecurityUploadEventAbstract());
    }

    /**
     * Return an instance of the TaskScheduler instance.
     * @return a TaskScheduler instance
     */
    public static TaskScheduler getInstance() {
        return INSTANCE;
    }

    private void scheduleConfigurableTask(final long initialDelay, final ConfigPropertyConstants enabledConstraint,
                                          final ConfigPropertyConstants constraint, final Event event) {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty enabledProperty = qm.getConfigProperty(
                    enabledConstraint.getGroupName(), enabledConstraint.getPropertyName());
            if (enabledProperty != null && enabledProperty.getPropertyValue() != null) {
                final boolean isEnabled = BooleanUtil.valueOf(enabledProperty.getPropertyValue());
                if (!isEnabled) {
                    return;
                }
            } else {
                return;
            }
            final ConfigProperty property = qm.getConfigProperty(constraint.getGroupName(), constraint.getPropertyName());
            if (property != null && property.getPropertyValue() != null) {
                final Integer minutes = Integer.valueOf(property.getPropertyValue());
                scheduleEvent(event, initialDelay, (long)minutes * (long)60 * (long)1000);
            }
        }
    }

    protected void scheduleNonParallelizedEvent(final ChainableEvent event, final long delay, final long period) {
        final Timer timer = new Timer();
        timer.schedule(new ScheduleNonParallelizedEvent().event(event), delay, period);
        timers.add(timer);
    }

    private class ScheduleNonParallelizedEvent extends TimerTask {
        private ChainableEvent event;

        /**
         * The Event that will be published
         * @param event the Event to publish
         * @return a new ScheduleEvent instance
         */
        public TaskScheduler.ScheduleNonParallelizedEvent event(final ChainableEvent event) {
            this.event = event;
            return this;
        }

        /**
         * Publishes the Event specified in the constructor.
         * This method publishes to all {@link EventService}s.
         */
        public void run() {
            synchronized (this) {
                EventService instance = EventService.getInstance();
                if (instance.isEventBeingProcessed(event)) {
                    LOGGER.warn("Skipping event '" + event.getClass().getSimpleName() + "' scheduling as previous iteration is still in progress");
                } else {
                    instance.publish(event);
                }
            }
        }
    }

    public void shutdown() {
        super.shutdown();

        for (final Timer timer: timers) {
            timer.cancel();
        }
    }
}
