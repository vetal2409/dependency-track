package org.dependencytrack.parser.npm;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.npm.model.Advisory;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;

import java.util.Date;

public final class NpmHelpers {
    /**
     * Helper method that maps an NPM advisory object to a Dependency-Track vulnerability object.
     * @param advisory the NPM advisory to map
     * @return a Dependency-Track Vulnerability object
     */
    public static Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final Advisory advisory) {
        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.NPM);
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setDescription(advisory.getOverview());
        vuln.setTitle(advisory.getTitle());
        vuln.setSubTitle(advisory.getModuleName());

        if (StringUtils.isNotBlank(advisory.getCreated())) {
            // final OffsetDateTime odt = OffsetDateTime.parse(advisory.getCreated());
            // vuln.setCreated(Date.from(odt.toInstant()));
            // vuln.setPublished(Date.from(odt.toInstant())); // Advisory does not have published, use created instead.

            // NPM introduced breaking API changes and no longer support ISO 8601 dates with offsets as documented in:
            // https://github.com/DependencyTrack/dependency-track/issues/676
            final Date date = DateUtil.fromISO8601(advisory.getCreated());
            vuln.setCreated(date);
            vuln.setPublished(date); // Advisory does not have published, use created instead.
        }
        if (StringUtils.isNotBlank(advisory.getUpdated())) {
            // final OffsetDateTime odt = OffsetDateTime.parse(advisory.getUpdated());
            // vuln.setUpdated(Date.from(odt.toInstant()));

            // NPM introduced breaking API changes and no longer support ISO 8601 dates with offsets as documented in:
            // https://github.com/DependencyTrack/dependency-track/issues/676
            final Date date = DateUtil.fromISO8601(advisory.getUpdated());
            vuln.setUpdated(date);
        }

        vuln.setCredits(advisory.getFoundBy());
        vuln.setRecommendation(advisory.getRecommendation());
        vuln.setReferences(advisory.getReferences());
        vuln.setVulnerableVersions(advisory.getVulnerableVersions());
        vuln.setPatchedVersions(advisory.getPatchedVersions());

        if (advisory.getCwe() != null) {
            final CweResolver cweResolver = new CweResolver(qm);
            final Cwe cwe = cweResolver.resolve(advisory.getCwe());
            vuln.setCwe(cwe);
        }

        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("Critical")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (advisory.getSeverity().equalsIgnoreCase("High")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (advisory.getSeverity().equalsIgnoreCase("Moderate")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (advisory.getSeverity().equalsIgnoreCase("Low")) {
                vuln.setSeverity(Severity.LOW);
            } else {
                vuln.setSeverity(Severity.UNASSIGNED);
            }
        } else {
            vuln.setSeverity(Severity.UNASSIGNED);
        }

        return vuln;
    }
}
