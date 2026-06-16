package org.ossreviewtoolkit.plugins.advisors.scorecard

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

import org.ossreviewtoolkit.model.Criticality
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.VcsType

class ScorecardTest : StringSpec({
    val scorecard = Scorecard(config = ScorecardConfig(apiUrl = "https://api.securityscorecards.dev"))

    "retrievePackageFindings for a valid package should return findings" {
        val pkg = Package(
            id = Identifier("VCS:oss-review-toolkit:ort:2.5.0"),
            declaredLicenses = emptySet(),
            description = "",
            homepageUrl = "",
            binaryArtifact = RemoteArtifact.EMPTY,
            sourceArtifact = RemoteArtifact.EMPTY,
            vcs = VcsInfo(
                type = VcsType.GIT,
                url = "https://github.com/oss-review-toolkit/ort.git",
                revision = "ddde192"
            ),
            vcsProcessed = VcsInfo(
                type = VcsType.GIT,
                url = "https://github.com/oss-review-toolkit/ort.git",
                revision = "ddde192"
            )
        )

        val result = scorecard.retrievePackageFindings(setOf(pkg))

        result shouldNotBe null
        result.keys.shouldNotBeEmpty()
        result.values.first().advisor shouldBe scorecard.details
        result.values.first().projectHealth.shouldNotBeEmpty()
    }

    "retrievePackageFindings for a package not known by scorecard should return empty health data" {
        val pkg = Package(
            id = Identifier("VCS:oss-review-toolkit:ort:2.5.0"),
            declaredLicenses = emptySet(),
            description = "",
            homepageUrl = "",
            binaryArtifact = RemoteArtifact.EMPTY,
            sourceArtifact = RemoteArtifact.EMPTY,
            vcs = VcsInfo.EMPTY,
            vcsProcessed = VcsInfo(
                type = VcsType.GIT,
                // This repository doesn't exist, and it never will because
                // these characters aren't allowed in a GitHub username
                url = "https://github.com/täßt/this-will-never-exist.git",
                revision = "ddde192"
            )
        )

        val result = scorecard.retrievePackageFindings(setOf(pkg))

        result shouldNotBe null
        result.keys shouldBe setOf(pkg)
        result.values.first().advisor shouldBe scorecard.details
        result.values.first().projectHealth.shouldBeEmpty()
    }

    "retrievePackageFindings for a package with no vcs should return empty health data" {
        val pkg = Package(
            id = Identifier("Maven:org.apache.logging.log4j:log4j-api:2.14.1"),
            declaredLicenses = emptySet(),
            description = "",
            homepageUrl = "",
            binaryArtifact = RemoteArtifact.EMPTY,
            sourceArtifact = RemoteArtifact.EMPTY,
            vcs = VcsInfo.EMPTY,
            vcsProcessed = VcsInfo.EMPTY
        )

        val result = scorecard.retrievePackageFindings(setOf(pkg))

        result shouldNotBe null
        result.keys shouldBe setOf(pkg)
        result.values.first().advisor shouldBe scorecard.details
        result.values.first().projectHealth.shouldBeEmpty()
    }

    "retrievePackageFindings for a malformed vcs url should return empty health data" {
        val pkg = Package(
            id = Identifier("Maven:org.apache.logging.log4j:log4j-api:2.14.1"),
            declaredLicenses = emptySet(),
            description = "",
            homepageUrl = "",
            binaryArtifact = RemoteArtifact.EMPTY,
            sourceArtifact = RemoteArtifact.EMPTY,
            vcs = VcsInfo.EMPTY,
            vcsProcessed = VcsInfo(
                type = VcsType.GIT,
                url = "https://invalid-url",
                revision = "ddde192"
            )
        )

        val result = scorecard.retrievePackageFindings(setOf(pkg))

        result shouldNotBe null
        result.keys shouldBe setOf(pkg)
        result.values.first().advisor shouldBe scorecard.details
        result.values.first().projectHealth.shouldBeEmpty()
    }

    "determineValueCriticality should return the correct criticality" {
        scorecard.determineValueCriticality(1) shouldBe Criticality.Critical
        scorecard.determineValueCriticality(2) shouldBe Criticality.Critical
        scorecard.determineValueCriticality(3) shouldBe Criticality.High
        scorecard.determineValueCriticality(4) shouldBe Criticality.High
        scorecard.determineValueCriticality(5) shouldBe Criticality.Medium
        scorecard.determineValueCriticality(7) shouldBe Criticality.Medium
        scorecard.determineValueCriticality(8) shouldBe Criticality.Low
        scorecard.determineValueCriticality(10) shouldBe Criticality.Low
    }
})
