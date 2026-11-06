package com.hyperos.privacyguard

import java.time.LocalDate

internal object UsageMetrics {
    const val RETENTION_DAYS = 30
    private val eventPattern = Regex("[a-z][a-z0-9_]{0,39}")

    fun increment(
        current: Map<String, Map<String, Int>>,
        date: String,
        event: String,
    ): Map<String, Map<String, Int>> {
        require(eventPattern.matches(event)) { "Invalid usage event" }
        val cutoff = LocalDate.parse(date).minusDays(RETENTION_DAYS - 1L).toString()
        val retained = current.filterKeys { it in cutoff..date }
        val events = retained[date].orEmpty().toMutableMap()
        events[event] = (events[event] ?: 0) + 1
        return retained + (date to events.toMap())
    }
}
