package org.ossreviewtoolkit.model

enum class Criticality {
    Low, Medium, High, Critical
}


data class ProjectHealth (
        /**
       * The name of project health metric.
       */
      val name: String? = null,


      /**
       * The metric score.
       */
    val value: Double? = null,

    /**
     * The metric crititcality.
     */
    val criticality: Criticality? = null,

    /**
     * The reason for the score.
     */
    val reason: String? = null,

    /**
     * Details about the findings.
     */
    val details: List<String>? = null,

    /**
     * Summary of documentation about the metric.
     */
    val documentation: String? = null,

    /**
     * Link to the documentation about the metric.
     */
    val documentationLink: String? = null,

    /**
     * Origin of evaluation.
     */
    val source: String
){


}
