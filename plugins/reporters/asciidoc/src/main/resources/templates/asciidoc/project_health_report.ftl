[#--
    Copyright (C) 2026 The ORT Project Copyright Holders <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    you may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    SPDX-License-Identifier: Apache-2.0
    License-Filename: LICENSE
--]

[#assign PurlUtils = statics['org.ossreviewtoolkit.model.utils.PurlExtensionsKt']]

:publisher: OSS Review Toolkit
[#assign now = .now]
:revdate: ${now?date?iso_local}

:title-page:
:sectnums:
:toc:

[#assign firstProjectId = projects?first.id]
[#assign firstProjectUrl = ortResult.getProject(firstProjectId).vcsProcessed.url]

= Project Health Report: Project ${firstProjectUrl}[${firstProjectId.name}], Version ${firstProjectId.version}

[#assign advisorResults = helper.advisorResultsWithProjectHealth()]

== Metrics Documentation

[#assign seenAdvisors = []]
[#list advisorResults?values as results]
[#list results as result]
[#assign advisorName = result.advisor.name]
[#if !seenAdvisors?seq_contains(advisorName)]
[#assign seenAdvisors = seenAdvisors + [advisorName]]
=== ${advisorName}

[#assign seenMetrics = []]
[#list advisorResults?values as innerResults]
[#list innerResults as innerResult]
[#if innerResult.advisor.name == advisorName]
[#list helper.filterProjectHealth(innerResult.projectHealth) as health]
[#if !seenMetrics?seq_contains(health.name) && health.documentationLink??]
[#assign seenMetrics = seenMetrics + [health.name]]
* *${health.name}*: link:++${health.documentationLink}++[${health.documentation!"Read more"}]
[/#if]
[/#list]
[/#if]
[/#list]
[/#list]

[/#if]
[/#list]
[/#list]

[#assign advisorResultsWithErrors = helper.advisorResultsWithIssues(Severity.ERROR)]
[#if advisorResultsWithErrors?has_content]
== Warning
[.alert]
Errors were encountered while retrieving project health information. Therefore, this report may be incomplete and
lack relevant metrics. Further details about the issues that occurred can be found in the
<<Packages with errors>> section.

<<<
[/#if]

== Packages
[#assign advisorResults = helper.advisorResultsWithProjectHealth()]
[#list advisorResults as id, results]
=== ${PurlUtils.toPurl(id)}

[#list results as result]

*Advisor: ${result.advisor.name}*

[#list helper.filterProjectHealth(result.projectHealth) as health]

* ${health.name}
** Value: ${health.value?string["0.00"]}
[#if health.criticality??]
** Criticality: [.severity-${health.criticality?lower_case}]#${health.criticality}#
[/#if]
[#if health.reason??]
** Reason: ${health.reason}
[/#if]
[#if health.details?has_content]
** Details:
[#list health.details as detail]
*** ${detail}
[/#list]
[/#if]

[/#list]

[#list result.summary.issues as issue]
* ${issue.severity}: ${issue.message}
[/#list]

[/#list]
[/#list]

[#if !advisorResults?has_content]
No packages with project health metrics have been found.
[/#if]

[#if advisorResultsWithErrors?has_content]
<<<
== Packages with errors

When retrieving project health information for these packages, the advisor module encountered errors. Therefore, it is
possible that existing metrics are missing from the report. This section lists the issues that
occurred when requesting project health information for the single packages.

[#list advisorResultsWithErrors as id, results]
=== ${id.name}

${PurlUtils.toPurl(id)}

[#list results as result]

[cols="1,5",options="header"]
|===
|Advisor|Message
[#list result.summary.issues as issue]
|${result.advisor.name}|${issue.message}
[/#list]
|===

[/#list]
[/#list]
[/#if]
