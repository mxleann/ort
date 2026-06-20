package org.ossreviewtoolkit.plugins.advisors.scorecard

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

import org.ossreviewtoolkit.model.Criticality

class ScorecardTest : StringSpec({
    val scorecard = Scorecard(config = ScorecardConfig(apiUrl = "https://api.securityscorecards.dev"))

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
