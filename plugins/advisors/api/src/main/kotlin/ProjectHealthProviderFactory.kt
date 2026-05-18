package org.ossreviewtoolkit.plugins.advisors.api

import java.util.ServiceLoader

import org.ossreviewtoolkit.plugins.api.PluginFactory

/**
 * A common abstract class for use with [ServiceLoader] that all [ProjectHealthProviderFactory] classes need to implement.
 */
interface ProjectHealthProviderFactory : PluginFactory<AdviceProvider> {
    companion object {
        /**
         * All [project health advice provider factories][ProjectHealthProviderFactory] available in the classpath, associated by their ids.
         */
        val ALL by lazy { PluginFactory.getAll<ProjectHealthProviderFactory, AdviceProvider>() }
    }
}
