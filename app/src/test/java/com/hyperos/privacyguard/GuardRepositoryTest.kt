package com.hyperos.privacyguard

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GuardRepositoryTest {
    @Test
    fun validPackageNamesAreAccepted() {
        assertTrue(GuardRepository.isValidPackageName("com.example.app"))
        assertTrue(GuardRepository.isValidPackageName("com.miui.securitycenter"))
        assertTrue(GuardRepository.isValidPackageName("a.b"))
    }

    @Test
    fun malformedPackageNamesAreRejected() {
        assertFalse(GuardRepository.isValidPackageName(""))
        assertTrue(GuardRepository.isValidPackageName("com.example"))
        assertFalse(GuardRepository.isValidPackageName("com.example."))
        assertFalse(GuardRepository.isValidPackageName("com..example.app"))
        assertFalse(GuardRepository.isValidPackageName("com.example/app"))
        assertFalse(GuardRepository.isValidPackageName("com.example.app;appops set"))
    }

    @Test
    fun appOpsCommandBoundaryAllowsOnlyReadOnlyTargetQuery() {
        GuardRepository.validateReadOnlyAppOpsArguments(listOf("get", "com.example.app", "GET_USAGE_STATS"))
        assertFalse(runCatching {
            GuardRepository.validateReadOnlyAppOpsArguments(listOf("set", "com.example.app", "GET_USAGE_STATS", "ignore"))
        }.isSuccess)
        assertFalse(runCatching {
            GuardRepository.validateReadOnlyAppOpsArguments(listOf("get", "com.example.app", "CAMERA"))
        }.isSuccess)
        assertFalse(runCatching {
            GuardRepository.validateReadOnlyAppOpsArguments(listOf("get", "com.example.app;id", "GET_USAGE_STATS"))
        }.isSuccess)
    }

    @Test
    fun appOpsParserRequiresAnExplicitKnownMode() {
        assertTrue(GuardRepository.parseUsageStatsMode("GET_USAGE_STATS: allow; time=+2m") == "allow")
        assertTrue(GuardRepository.parseUsageStatsMode("Uid mode: GET_USAGE_STATS: ignore") == "ignore")
        assertTrue(GuardRepository.parseUsageStatsMode("No operations.") == null)
        assertTrue(GuardRepository.parseUsageStatsMode("GET_USAGE_STATS: mystery") == null)
    }

    @Test
    fun componentSignalsExposeOnlyDeclaredCapabilities() {
        val component = SystemComponent(
            packageName = "com.example.component",
            label = "Example",
            uid = 12345,
            versionName = "1",
            versionCode = 1,
            category = "第三方组件",
            isSystem = false,
            permissions = setOf(
                "android.permission.PACKAGE_USAGE_STATS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
            ),
            signatureSha256 = "",
        )
        assertTrue(component.requestsUsageStats)
        assertTrue("应用活动记录" in component.privacySignals)
        assertTrue("位置" in component.privacySignals)
        assertTrue("联系人" in component.privacySignals)
        assertTrue("麦克风/相机/媒体" in component.privacySignals)
    }

    @Test
    fun usageMetricsAggregateEventsAndPruneDaysOutsideRetention() {
        val initial = mapOf(
            "2026-10-01" to mapOf("app_launch" to 2),
            "2026-10-09" to mapOf("page_home" to 4),
            "2026-11-07" to mapOf("app_launch" to 1),
        )

        val updated = UsageMetrics.increment(initial, "2026-11-07", "page_settings")
        assertFalse("2026-10-01" in updated)
        assertEquals(4, updated["2026-10-09"]?.get("page_home"))
        assertEquals(1, updated["2026-11-07"]?.get("page_settings"))
        assertEquals(1, updated["2026-11-07"]?.get("app_launch"))
    }

    @Test
    fun usageMetricsRejectInvalidEventNames() {
        assertFalse(runCatching {
            UsageMetrics.increment(emptyMap(), "2026-11-07", "com.example.secret")
        }.isSuccess)
    }
}
