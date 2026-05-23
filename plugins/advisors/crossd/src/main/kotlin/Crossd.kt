/*
 * Copyright (C) 2026 The ORT Project Copyright Holders <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.plugins.advisors.crossd

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.async
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

import org.ossreviewtoolkit.model.AdvisorDetails
import org.ossreviewtoolkit.model.AdvisorResult
import org.ossreviewtoolkit.model.AdvisorSummary
import org.ossreviewtoolkit.model.Criticality
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.ProjectHealth
import org.ossreviewtoolkit.plugins.advisors.api.AdviceProvider
import org.ossreviewtoolkit.plugins.advisors.api.AdviceProviderFactory
import org.ossreviewtoolkit.plugins.api.OrtPlugin
import org.ossreviewtoolkit.plugins.api.PluginDescriptor
import org.ossreviewtoolkit.utils.ort.okHttpClient
import java.io.IOException
import java.time.Instant
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.collections.emptyMap


/**
 * An [AdviceProvider] implementation that obtains security vulnerability information from a
 * [CrOSSD][https://health.crossd.tech/doc] instance.
 */
@OrtPlugin(
    id = "Crossd",
    displayName = "CrOSSD",
    description = "An advisor that uses a CrOSSD instance to determine project health in dependencies.",
    factory = AdviceProviderFactory::class
)

class Crossd (
    override val descriptor: PluginDescriptor = CrossdFactory.descriptor,
    config: CrossdConfig
) : AdviceProvider {

    private val client = HttpClient(OkHttp) {
        engine {
            preconfigured = okHttpClient
        }

        install(DefaultRequest) {
            url(config.apiUrl)
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }

        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                coerceInputValues = true
            })
        }
    }

    override val details = AdvisorDetails(descriptor.id)

    var averages: Map<String, Double> = emptyMap()


    override suspend fun retrievePackageFindings(packages: Set<Package>): Map<Package, AdvisorResult> {
        // update average values that are used for the value ratings
        updateAverageValues()

        val startTime = Instant.now()
        val issues = mutableListOf<Issue>()
        val regex = """^[a-z]+://[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+/([a-zA-Z0-9-_]+/[a-zA-Z0-9-_]+)(?:\.git)?$""".toRegex()

        // find project owner and name from git URL and report missing ones
        val packageIds = packages.associateWith { regex.find(it.vcsProcessed.url)?.groupValues[1] }
        packageIds.filterValues{it == null}.mapTo(issues) { pkg ->
            Issue(
                source = descriptor.displayName,
                message = "The VCS URL '${pkg.key.vcsProcessed.url}' could not be mapped to a repository."
            )
        }

        // query the actual metrics data
        val metrics = packageIds.mapValues {
            it.value?.let { packageId ->
                getMetrics(packageId)
            } ?: emptyList()
        }

        val endTime = Instant.now()

        return metrics.mapValues {
            AdvisorResult(details, AdvisorSummary(startTime, endTime, issues), emptyList(), it.value)
        }
    }

    suspend fun updateAverageValues() {
        val response = client.post("/api/metrics/avg")
        if (!response.status.isSuccess())
            return

        val avg = (response.body() as JsonObject)["avg"]?.jsonObject
            ?: return

        averages = avg.entries.associate { (key, value) ->
            key to value.jsonPrimitive.double
        }
    }

    suspend fun getAvailableSnapshots(packageId: String): List<Double> {
        val response = client.post("/api/snapshots") {
          setBody(buildJsonObject {
              put("term", packageId)
          })
        }

        if (!response.status.isSuccess())
            return emptyList()

        return (response.body() as JsonArray).map { it.jsonPrimitive.double }.sortedDescending()
    }

    suspend fun getLatestSnapshot(packageId: String): Double? {
        return getAvailableSnapshots(packageId).getOrNull(0)
    }

    suspend fun getMetrics(packageId: String, snapshot: Double): List<ProjectHealth> {
        val response = client.post("/api/metrics") {
            setBody(buildJsonObject {
                put("term", packageId)
                put("timestamp", snapshot)
            })
        }

        if (!response.status.isSuccess())
            return emptyList()

        val metrics = (response.body() as JsonObject)["metrics"]?.jsonObject
            ?: return emptyList()

        return CROSSD_METRICS.flatMap { metric ->
            val value = metric.valueGetter(metrics)
            value?.let {
                listOf(ProjectHealth(
                    name = metric.name,
                    value = value,
                    criticality = metric.getCriticality(value, averages[metric.name]),
                    documentation = metric.descriptionShort,
                    documentationLink = metric.documentationUrl,
                    details = emptyList(),
                    source = descriptor.id
                ))
            } ?: emptyList()
        }
    }

    suspend fun getMetrics(packageId: String): List<ProjectHealth> {
        return getLatestSnapshot(packageId)?.let {
            return getMetrics(packageId, it)
        } ?: emptyList()
    }
}
