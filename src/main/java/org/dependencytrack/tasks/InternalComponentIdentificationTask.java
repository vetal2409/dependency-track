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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.persistence.PaginatedResult;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentificationUtil;

import java.util.List;

/**
 * Subscriber task that identifies internal components throughout the entire portfolio.
 *
 * @author nscuro
 * @since 3.7.0
 */
public class InternalComponentIdentificationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalComponentIdentificationTask.class);

    @Override
    public void inform(final Event e) {
        if (!(e instanceof InternalComponentIdentificationEvent)) {
            return;
        }
        final InternalComponentIdentificationEvent event = (InternalComponentIdentificationEvent)e;

        try (final QueryManager qm = new QueryManager(0, 200)) {
            if (event.getComponents().size() > 0) {
                LOGGER.info("Starting internal component identification task for " + event.getComponents().size() + "components");
                analyze(qm, event.getComponents());
                LOGGER.info("Internal component identification task completed");
            } else {
                LOGGER.info("Starting, portfolio wide, internal component identification task");
                final long total = qm.getCount(Component.class);
                long count = 0;
                while (count < total) {
                    final PaginatedResult result = qm.getComponents();
                    final List<Component> components = result.getList(Component.class);

                    analyze(qm, components);

                    count += result.getObjects().size();
                    LOGGER.info("Completed identification of " + count + " out of " + total + " components");
                    qm.advancePagination();
                }

                LOGGER.info("Internal, portfolio wide, component identification task completed");
            }
        }
    }

    private void analyze(final QueryManager qm, final List<Component> components) {
        for (final Component component : components) {
            final boolean internal = InternalComponentIdentificationUtil.isInternalComponent(component, qm);
            if (internal) {
                LOGGER.debug("Component " + component + " was identified to be internal");
            }
            if (component.isInternal() != internal) { // We want to log changes to a component's internal status.
                if (internal) {
                    LOGGER.info("Component " + component + " was identified to be internal. It was previously not an internal component.");
                } else {
                    LOGGER.info("Component " + component + " was previously identified as an internal component. It is no longer identified as internal.");
                }
            }
            if (component.isInternal() != internal) {
                component.setInternal(internal);
                qm.persist(component);
            }
        }
    }

}
