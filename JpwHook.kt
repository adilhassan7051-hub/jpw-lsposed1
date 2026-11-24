package com.jpwreach.lsposed

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.Location
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.Toast
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.TreeMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

/**
 * JPW Auto-Reach LSPosed module.
 */
class JpwHook : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "JpwHook"
        private const val TARGET_PKG = "com.jio.jpss"
        private fun log(s: String) = XposedBridge.log("[$TAG] $s")
    }

    private var capturedAuthHeader: String = ""
    private var capturedJioCenterId: String = ""
    private val sessionCookies = mutableMapOf<String, String>()

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PKG) return
        log("Loaded into ${lpparam.packageName}")

        val cl = lpparam.classLoader

        // ── 1. Mock-Location & Dev-Settings system-level bypass ──
        bypassMockLocation()
        bypassDeveloperSettings()

        // ── 2. RootBeer / SU detection bypass ──
        bypassRootBeer(cl)

        // ── 3. AppSecurityModule check methods bypass ──
        bypassAppSecurityModule(cl)

        // ── 4. OTP flow bypass (SendOtp / VerifyOtp) ──
        bypassOtpFlow(cl)

        // ── 5. Inject Auto-Reach FAB into MainActivity ──
        injectAutoReachButton(cl)

        // ── 6. SIM verification bypass (TelephonyManager) ──
        bypassSimVerification(cl)

        // ── 7. App signature + integrity check bypass ──
        bypassSignatureAndIntegrity(cl)

        // ── 8. Auto-capture cookies & headers from all HTTP requests/responses ──
        hookHttpCookieCapture(cl)

        // ── 9. Broadcast trigger for headless REACH ──
        registerBroadcastTrigger(cl)
    }

    // ─── 1. Mock location → always false ───
    private fun bypassMockLocation() {
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isFromMockProvider",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isFromMockProvider → false")
        } catch (t: Throwable) { log("✗ isFromMockProvider: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isMock",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isMock → false")
        } catch (_: Throwable) {}

        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
            log("✓ Hooked Settings.Secure.getInt mock_location → 0")
        } catch (t: Throwable) { log("✗ Settings.Secure 2-arg: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }

    // ─── 2. Developer options & ADB → 0 ───
    private fun bypassDeveloperSettings() {
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(p: MethodHookParam) {
                val k = p.args[1] as String?
                if (k == "development_settings_enabled" || k == "adb_enabled") {
                    p.result = 0
                }
            }
        }
        for (klass in listOf(Settings.Global::class.java, Settings.Secure::class.java, Settings.System::class.java)) {
            for (sig in listOf(
                arrayOf(android.content.ContentResolver::class.java, String::class.java),
                arrayOf(android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType),
            )) {
                try { XposedHelpers.findAndHookMethod(klass, "getInt", *sig, hook) } catch (_: Throwable) {}
            }
        }
        log("✓ Hooked Settings.*.getInt dev/adb → 0")
    }

    // ─── 3. RootBeer + SU checks → false ───
    private fun bypassRootBeer(cl: ClassLoader) {
        val rootBeerNames = listOf(
            "com.scottyab.rootbeer.RootBeer",
            "com.scottyab.rootbeer.RootBeerNative",
        )
        for (clsName in rootBeerNames) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    if (m.returnType == Boolean::class.javaPrimitiveType) {
                        try {
                            XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false))
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $clsName (all boolean methods → false)")
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 4. AppSecurityModule check methods bypass ───
    private fun bypassAppSecurityModule(cl: ClassLoader) {
        val classes = listOf(
            "com.jio.jpss.AppSecurityModule",
            "com.jio.jpss.AppSecurityModule\$Companion",
        )
        val matchKeywords = listOf(
            "isRoot", "checkRoot", "isMock", "checkMock", "isDevelop", "checkDevelop",
            "isEmulator", "checkEmulator", "isDebugger", "checkDebugger",
            "verifyOtp", "isOtpRequired", "needOtp", "isVerified", "checkOtp"
        )
        for (clsName in classes) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    val name = m.name
                    val matches = matchKeywords.any { name.contains(it, ignoreCase = true) }
                    if (!matches) return@forEach
                    try {
                        val rt = m.returnType
                        val replacement = when {
                            rt == Boolean::class.javaPrimitiveType ->
                                if (name.contains("verify", true) || name.contains("isVerified", true))
                                    XC_MethodReplacement.returnConstant(true)
                                else XC_MethodReplacement.returnConstant(false)
                            rt == Int::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(0)
                            rt == String::class.java ->
                                XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, replacement)
                        log("✓ Hooked $clsName.$name → bypass")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 5. OTP flow short-circuit ───
    private fun bypassOtpFlow(cl: ClassLoader) {
        val targets = listOf(
            "com.jio.jpss.asynctask.SendOtp",
            "com.jio.jpss.asynctask.VerifyOtp",
        )
        for (t in targets) {
            try {
                val cls = XposedHelpers.findClass(t, cl)
                cls.declaredMethods.forEach { m ->
                    if (m.name == "doInBackground") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodReplacement() {
                                override fun replaceHookedMethod(p: MethodHookParam): Any? {
                                    log("OTP shortcircuit: $t.doInBackground returning fake-success")
                                    return """{"IsSuccessful":true,"Status":"VERIFIED","Message":"OK"}"""
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                    if (m.name == "onPostExecute") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                                override fun beforeHookedMethod(p: MethodHookParam) {
                                    log("OTP onPostExecute called for $t — letting through")
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $t (OTP shortcircuit)")
            } catch (_: Throwable) {
                log("ℹ $t not present")
            }
        }
    }

    // ─── 6. Inject Auto-Reach floating button ───
    private fun injectAutoReachButton(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(
                mainCls, "onCreate", Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        val act = p.thisObject as Activity
                        addFab(act)
                    }
                }
            )
            log("✓ Hooked MainActivity.onCreate (FAB inject)")
        } catch (t: Throwable) {
            log("✗ FAB inject failed: $t")
        }
    }

    private fun addFab(activity: Activity) {
        try {
            activity.window.decorView.post {
                val root = activity.findViewById<FrameLayout>(android.R.id.content)
                if (root == null || root.findViewWithTag<View>("jpw_auto_reach_fab") != null) return@post

                val ctx = activity
                val fab = android.widget.Button(ctx).apply {
                    text = "⚡ AUTO-REACH"
                    setTextColor(android.graphics.Color.WHITE)
                    textSize = 13f
                    setPadding(dp(ctx, 16), dp(ctx, 10), dp(ctx, 16), dp(ctx, 10))
                    background = makeRedGradient(ctx)
                    elevation = dp(ctx, 8).toFloat()
                    tag = "jpw_auto_reach_fab"
                    setOnClickListener { onAutoReachClicked(ctx) }
                }
                val lp = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    gravity = Gravity.BOTTOM or Gravity.END
                    rightMargin = dp(ctx, 16)
                    bottomMargin = dp(ctx, 24)
                }
                root.addView(fab, lp)
                log("✓ AUTO-REACH button injected into MainActivity")
            }
        } catch (t: Throwable) {
            log("addFab failed: $t")
        }
    }

    private fun onAutoReachClicked(ctx: Context) {
        val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
        val savedPass = prefs.getString("password", "") ?: prefs.getString("Password", "") ?: ""
        val savedTechId = prefs.getString("technician_id", "") ?: ""

        // If we already captured active cookies or Authorization header from the running app, run immediately!
        val hasLiveSession = sessionCookies.isNotEmpty() || capturedAuthHeader.isNotEmpty()

        if (!hasLiveSession && (savedPass.isEmpty() || savedTechId.isEmpty())) {
            if (ctx is Activity) {
                val lp = android.widget.LinearLayout(ctx).apply {
                    orientation = android.widget.LinearLayout.VERTICAL
                    setPadding(48, 24, 48, 16)
                }
                val techIdField = android.widget.EditText(ctx).apply {
                    hint = "Enter Technician ID"
                    inputType = android.text.InputType.TYPE_CLASS_TEXT
                    if (savedTechId.isNotEmpty()) setText(savedTechId)
                }
                val passField = android.widget.EditText(ctx).apply {
                    hint = "Enter JPW password"
                    inputType = android.text.InputType.TYPE_CLASS_TEXT or
                                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                    if (savedPass.isNotEmpty()) setText(savedPass)
                }
                lp.addView(techIdField)
                lp.addView(passField)
                android.app.AlertDialog.Builder(ctx)
                    .setTitle("Login Required")
                    .setMessage("Enter Technician ID and JPW password:")
                    .setView(lp)
                    .setPositiveButton("Save & Run") { _, _ ->
                        val id = techIdField.text.toString().trim()
                        val pass = passField.text.toString().trim()
                        if (id.isNotEmpty() && pass.isNotEmpty()) {
                            prefs.edit().putString("technician_id", id).putString("password", pass).apply()
                            Toast.makeText(ctx, "Credentials saved! Starting REACH…", Toast.LENGTH_SHORT).show()
                            Thread {
                                try { autoReach(ctx) } catch (t: Throwable) {
                                    log("autoReach error: $t")
                                    showToast(ctx, "REACH failed: ${t.message}")
                                }
                            }.start()
                        } else {
                            Toast.makeText(ctx, "Both Technician ID and Password are required", Toast.LENGTH_SHORT).show()
                        }
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }
            return
        }

        Toast.makeText(ctx, "Auto-Reach: running inside JPW process…", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                autoReach(ctx)
            } catch (t: Throwable) {
                log("autoReach error: $t")
                showToast(ctx, "REACH failed: ${t.message}")
            }
        }.start()
    }

    private val REACH_URL = "https://jpw.jio.com/lco/api/workorder-maintenance/WorkOrder/UpdateWorkOrder"
    private val WO_URL = "https://jpw.jio.com/lco/api/workorder-inquiry/WorkOrder/GetWorkOrderList"
    private val LOGIN_URL = "https://jpw.jio.com/api/login/SAML/UserLogin"
    private val PREF_NAME = "jpwreach_lsposed_prefs"
    private val APP_VERSION = "2.1.0"
    private val DEVICE_ID = "ffae0907fcc794e3"
    private val FCM_ID = "eXVTratwRhW6CXT6phHtuD:APA91bGQ2Q4nGz9W6haWztTixJB98ZcLxoi7UUO8pV26f-UAj0-OYRQPUb8WVhxTlXglmJDW57j0FuFhl0bXUOhk9a5cvhLEcNwiGWgHISlRQ45GK11OHBI"

    private val HMAC_SECRET = "2f41ab9cd96ef54252ea0185be4e6e87"
    private val CUST_PLAN_HARDCODED = "YGNyzBQYJRQy/Qa9bN1uyTkeuJ8d5v1KIkSK/hKK7KJntzp+rDEBIB1NZ0VUTpr40HqAKt3FZlTbsut9QHECWsMdwiu/0hW6BsMxx08YqLE="

    private fun autoReach(ctx: Context) {
        showToast(ctx, "Step 1/4: Getting session…")

        loadCookies(ctx)

        val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
        val jioCenterId = capturedJioCenterId.ifEmpty { prefs.getString("jio_center_id", "") ?: "" }
        val techId = prefs.getString("user_id", "") ?:
                    prefs.getString("UserID", "") ?:
                    prefs.getString("technician_id", "") ?:
                    prefs.getString("TechnicianID", "") ?: ""
        log("Cookies: ${sessionCookies.size}, Auth: ${capturedAuthHeader.isNotEmpty()}, JioCenter: $jioCenterId, TechId: $techId")

        if (sessionCookies.isEmpty() && capturedAuthHeader.isEmpty() && techId.isNotEmpty()) {
            val techPass = prefs.getString("password", "") ?:
                          prefs.getString("Password", "") ?: ""
            if (techPass.isNotEmpty()) {
                showToast(ctx, "No session. Logging in...")
                doLogin(ctx, techId, techPass)
            }
        }

        if (sessionCookies.isEmpty() && capturedAuthHeader.isEmpty()) {
            showToast(ctx, "No session — Tap Refresh icon (↻) at top right first!")
            return
        }

        // Step 2: Fetch work orders
        showToast(ctx, "Step 2/4: Fetching WOs…")
        val woPayload = JSONObject()
        if (techId.isNotEmpty()) woPayload.put("TechnicianID", techId)
        woPayload.put("IsHSOUser", false)
        woPayload.put("WorkOrderStatus", JSONArray().put(""))
        woPayload.put("PageSize", 200)
        woPayload.put("offsetValue", 0)
        woPayload.put("TechnicianDesignationType", "Technician")

        val woHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/v1/workOrderListV3")
        if (jioCenterId.isNotEmpty()) woHeaders["X-JioCenterId"] = jioCenterId
        val woResult = httpPostNoSig(WO_URL, woPayload.toString(), woHeaders)
        log("WO response: ${woResult.substring(0, minOf(500, woResult.length))}")

        val woJson = try { JSONObject(woResult) } catch (e: Exception) {
            log("WO JSON parse error: $e, raw: $woResult")
            showToast(ctx, "WO fetch failed! Tap Refresh (↻) and try again.")
            return
        }
        if (!woJson.optBoolean("IsSuccessful", false)) {
            val err = woJson.optString("Message", "unknown")
            showToast(ctx, "WO fetch failed: $err")
            return
        }
        val orders = woJson.optJSONArray("lstWorkOrders") ?: JSONArray()
        val total = orders.length()
        showToast(ctx, "Step 3/4: REACHing $total WOs…")

        // Step 3: REACH each WO
        var success = 0
        var fail = 0
        for (i in 0 until total) {
            val wo = orders.getJSONObject(i)
            val woId = wo.optString("WorkOrderID", "")
            if (woId.isEmpty()) continue
            val subType = wo.optString("WorkOrderSubType", "22")
            val woType = wo.optString("WorkOrderType", "ZFVO")
            val address = wo.optJSONObject("CustomerDetails")?.optJSONObject("Address") ?: JSONObject()
            val buildingId = address.optString("BuildingID", "")
            val lat = address.optDouble("Latitude", 23.950524158)
            val lng = address.optDouble("Longitude", 87.676930303)
            val custPlan = wo.optString("CustomerPlan", "")
            val assignedTech = wo.optString("TechnicianID", techId)

            val reachPayload = JSONObject()
            reachPayload.put("ActionCode
