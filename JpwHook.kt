package com.jpwreach.lsposed

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.Location
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.webkit.CookieManager
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

class JpwHook : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "JpwHook"
        private const val TARGET_PKG = "com.jio.jpss"
        private fun log(s: String) = XposedBridge.log("[$TAG]$s")
    }

    private var capturedAuthHeader: String = ""
    private var capturedJioCenterId: String = ""
    private val sessionCookies = mutableMapOf<String, String>()

    private val REACH_URL = "https://jpw.jio.com/lco/api/workorder-maintenance/WorkOrder/UpdateWorkOrder"
    private val WO_URL = "https://jpw.jio.com/lco/api/workorder-inquiry/WorkOrder/GetWorkOrderList"
    private val LOGIN_URL = "https://jpw.jio.com/api/login/SAML/UserLogin"
    private val PREF_NAME = "jpwreach_lsposed_prefs"
    private val APP_VERSION = "2.1.2"
    private val DEVICE_ID = "ffae0907fcc794e3"
    private val FCM_ID = "eXVTratwRhW6CXT6phHtuD:APA91bGQ2Q4nGz9W6haWztTixJB98ZcLxoi7UUO8pV26f-UAj0-OYRQPUb8WVhxTlXglmJDW57j0FuFhl0bXUOhk9a5cvhLEcNwiGWgHISlRQ45GK11OHBI"
    private val HMAC_SECRET = "2f41ab9cd96ef54252ea0185be4e6e87"
    private val CUST_PLAN_HARDCODED = "YGNyzBQYJRQy/Qa9bN1uyTkeuJ8d5v1KIkSK/hKK7KJntzp+rDEBIB1NZ0VUTpr40HqAKt3FZlTbsut9QHECWsMdwiu/0hW6BsMxx08YqLE="

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PKG) return
        val cl = lpparam.classLoader
        bypassMockLocation()
        bypassDeveloperSettings()
        bypassRootBeer(cl)
        bypassAppSecurityModule(cl)
        bypassOtpFlow(cl)
        injectAutoReachButton(cl)
        bypassSimVerification(cl)
        bypassSignatureAndIntegrity(cl)
        hookHttpCookieCapture(cl)
        registerBroadcastTrigger(cl)
    }

    private fun extractWebViewCookies() {
        try {
            val cm = CookieManager.getInstance()
            val rawCookies = cm.getCookie("https://jpw.jio.com") ?: ""
            if (rawCookies.isNotEmpty()) {
                rawCookies.split(";").forEach {
                    val p = it.split("=", limit = 2)
                    if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
                }
            }
        } catch (_: Throwable) {}
    }

    private fun bypassMockLocation() {
        try { XposedHelpers.findAndHookMethod(Location::class.java, "isFromMockProvider", XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
        try { XposedHelpers.findAndHookMethod(Location::class.java, "isMock", XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(p: MethodHookParam) {
                val k = p.args[1] as String?
                if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") p.result = 0
            }
        }
        try { XposedHelpers.findAndHookMethod(Settings.Secure::class.java, "getInt", android.content.ContentResolver::class.java, String::class.java, hook) } catch (_: Throwable) {}
        try { XposedHelpers.findAndHookMethod(Settings.Secure::class.java, "getInt", android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType, hook) } catch (_: Throwable) {}
    }

    private fun bypassDeveloperSettings() {
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(p: MethodHookParam) {
                val k = p.args[1] as String?
                if (k == "development_settings_enabled" || k == "adb_enabled") p.result = 0
            }
        }
        for (klass in listOf(Settings.Global::class.java, Settings.Secure::class.java, Settings.System::class.java)) {
            for (sig in listOf(arrayOf(android.content.ContentResolver::class.java, String::class.java), arrayOf(android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType))) {
                try { XposedHelpers.findAndHookMethod(klass, "getInt", *sig, hook) } catch (_: Throwable) {}
            }
        }
    }

    private fun bypassRootBeer(cl: ClassLoader) {
        for (clsName in listOf("com.scottyab.rootbeer.RootBeer", "com.scottyab.rootbeer.RootBeerNative")) {
            try {
                XposedHelpers.findClass(clsName, cl).declaredMethods.forEach { m ->
                    if (m.returnType == Boolean::class.javaPrimitiveType) try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {}
        }
    }

    private fun bypassAppSecurityModule(cl: ClassLoader) {
        val kw = listOf("isRoot", "checkRoot", "isMock", "checkMock", "isDevelop", "checkDevelop", "isEmulator", "checkEmulator", "isDebugger", "checkDebugger", "verifyOtp", "isOtpRequired", "needOtp", "isVerified", "checkOtp")
        for (clsName in listOf("com.jio.jpss.AppSecurityModule", "com.jio.jpss.AppSecurityModule\$Companion")) {
            try {
                XposedHelpers.findClass(clsName, cl).declaredMethods.forEach { m ->
                    if (kw.none { m.name.contains(it, ignoreCase = true) }) return@forEach
                    try {
                        val rep = when (m.returnType) {
                            Boolean::class.javaPrimitiveType -> if (m.name.contains("verify", true) || m.name.contains("isVerified", true)) XC_MethodReplacement.returnConstant(true) else XC_MethodReplacement.returnConstant(false)
                            Int::class.javaPrimitiveType -> XC_MethodReplacement.returnConstant(0)
                            String::class.java -> XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, rep)
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {}
        }
    }

    private fun bypassOtpFlow(cl: ClassLoader) {
        for (t in listOf("com.jio.jpss.asynctask.SendOtp", "com.jio.jpss.asynctask.VerifyOtp")) {
            try {
                XposedHelpers.findClass(t, cl).declaredMethods.forEach { m ->
                    if (m.name == "doInBackground") try {
                        XposedBridge.hookMethod(m, object : XC_MethodReplacement() {
                            override fun replaceHookedMethod(p: MethodHookParam): Any? = """{"IsSuccessful":true,"Status":"VERIFIED","Message":"OK"}"""
                        })
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {}
        }
    }

    private fun injectAutoReachButton(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(mainCls, "onCreate", Bundle::class.java, object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) { addFab(p.thisObject as Activity) }
            })
        } catch (_: Throwable) {}
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
                val lp = FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT).apply {
                    gravity = Gravity.BOTTOM or Gravity.END
                    rightMargin = dp(ctx, 16)
                    bottomMargin = dp(ctx, 24)
                }
                root.addView(fab, lp)
            }
        } catch (_: Throwable) {}
    }

    private fun onAutoReachClicked(ctx: Context) {
        extractWebViewCookies()
        loadCookies(ctx)
        val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val savedPass = prefs.getString("password", "") ?: ""
        val savedTechId = prefs.getString("technician_id", "") ?: ""

        if (sessionCookies.isNotEmpty() || capturedAuthHeader.isNotEmpty()) {
            Thread { autoReach(ctx) }.start()
            return
        }

        if (ctx is Activity) {
            val lp = android.widget.LinearLayout(ctx).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                setPadding(48, 24, 48, 16)
            }
            val techIdField = android.widget.EditText(ctx).apply {
                hint = "Enter Technician ID"
                if (savedTechId.isNotEmpty()) setText(savedTechId)
            }
            val passField = android.widget.EditText(ctx).apply {
                hint = "Enter JPW password"
                inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                if (savedPass.isNotEmpty()) setText(savedPass)
            }
            lp.addView(techIdField)
            lp.addView(passField)

            android.app.AlertDialog.Builder(ctx)
                .setTitle("Login Required")
                .setMessage("Enter Technician ID and JPW password:")
                .setView(lp)
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("SAVE & RUN") { _, _ ->
                    val tid = techIdField.text.toString().trim()
                    val pwd = passField.text.toString().trim()
                    if (tid.isNotEmpty() && pwd.isNotEmpty()) {
                        prefs.edit().putString("technician_id", tid).putString("password", pwd).apply()
                        Thread {
                            if (doLogin(ctx, tid, pwd)) {
                                autoReach(ctx)
                            } else {
                                showToast(ctx, "No session — login failed or missing. Check credentials.")
                            }
                        }.start()
                    } else {
                        showToast(ctx, "Enter both Technician ID and Password")
                    }
                }
                .show()
        }
    }

    private fun autoReach(ctx: Context) {
        showToast(ctx, "Step 1/4: Getting session…")
        Handler(Looper.getMainLooper()).post { extractWebViewCookies() }
        Thread.sleep(300)
        loadCookies(ctx)

        val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val jioCenterId = capturedJioCenterId.ifEmpty { prefs.getString("saved_center", "") ?: "" }
        val techId = prefs.getString("technician_id", "") ?: ""

        if (sessionCookies.isEmpty() && capturedAuthHeader.isEmpty() && techId.isNotEmpty()) {
            val techPass = prefs.getString("password", "") ?: ""
            if (techPass.isNotEmpty()) doLogin(ctx, techId, techPass)
        }
        if (sessionCookies.isEmpty() && capturedAuthHeader.isEmpty()) {
            showToast(ctx, "No session — login failed or missing. Check credentials.")
            return
        }

        showToast(ctx, "Step 2/4: Fetching WOs…")
        val woPayload = JSONObject().apply {
            if (techId.isNotEmpty()) put("TechnicianID", techId)
            put("IsHSOUser", false)
            put("WorkOrderStatus", JSONArray().put(""))
            put("PageSize", 200)
            put("offsetValue", 0)
            put("TechnicianDesignationType", "Technician")
        }
        val woHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/v1/workOrderListV3")
        if (jioCenterId.isNotEmpty()) woHeaders["X-JioCenterId"] = jioCenterId
        val woResult = httpPostNoSig(WO_URL, woPayload.toString(), woHeaders)

        val woJson = try { JSONObject(woResult) } catch (_: Exception) {
            showToast(ctx, "WO fetch failed! Tap Refresh (↻) and try again.")
            return
        }
        if (!woJson.optBoolean("IsSuccessful", false)) {
            showToast(ctx, "WO fetch failed: ${woJson.optString("Message", "unknown")}")
            return
        }
        val orders = woJson.optJSONArray("lstWorkOrders") ?: JSONArray()
        val total = orders.length()
        showToast(ctx, "Step 3/4: REACHing $total WOs…")

        var success = 0
        var fail = 0
        for (i in 0 until total) {
            val wo = orders.getJSONObject(i)
            val woId = wo.optString("WorkOrderID", "")
            if (woId.isEmpty()) continue
            val subType = wo.optString("WorkOrderSubType", "22")
            val woType = wo.optString("WorkOrderType", "ZFVO")
            val address = wo.optJSONObject("CustomerDetails")?.optJSONObject("Address") ?: JSONObject()
            val reachPayload = JSONObject().apply {
                put("ActionCode", "ZA26")
                put("BuildingID", address.optString("BuildingID", ""))
                put("StatusCode", "CL09")
                put("TechnicianLatitude", address.optDouble("Latitude", 23.950524158).toString())
                put("TechnicianLongitude", address.optDouble("Longitude", 87.676930303).toString())
                put("UpdatedBy", wo.optString("TechnicianID", techId))
                put("WorkOrderID", woId)
                put("WorkOrderSubType", subType)
                put("WorkOrderType", woType)
                put("woForC6Customer", subType in listOf("13", "15"))
                put("CustomerPlan", wo.optString("CustomerPlan", "").ifEmpty { CUST_PLAN_HARDCODED })
            }
            val reachHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/retailv1/workOrderV3/reached")
            if (jioCenterId.isNotEmpty()) reachHeaders["X-JioCenterId"] = jioCenterId
            try {
                val bodyStr = toSortedJsonString(reachPayload)
                reachHeaders["X-Signature"] = generateSignature(bodyStr)
                if (JSONObject(httpPostNoSig(REACH_URL, bodyStr, reachHeaders)).optBoolean("IsSuccessful", false)) success++ else fail++
            } catch (_: Exception) { fail++ }
        }
        showToast(ctx, "Done! REACHED: $success, Failed: $fail out of $total")
    }

    private fun doLogin(ctx: Context, techId: String, techPass: String): Boolean {
        val payload = JSONObject().apply {
            put("UserName", techId)
            put("Password", techPass)
            put("Handset", "android")
            put("FCMID", FCM_ID)
            put("DeviceId", DEVICE_ID)
            put("AppVersion", APP_VERSION)
        }
        return try {
            val json = JSONObject(httpPostNoSig(LOGIN_URL, payload.toString(), mapOf("Referer" to "https://jpw.jio.com/v1/OIDLOGIN")))
            if (json.optBoolean("IsSuccessful", false)) {
                val sid = json.optString("sessionId", "")
                if (sid.isNotEmpty()) sessionCookies["JPSSSessionID"] = sid
                saveCookies(ctx)
                true
            } else false
        } catch (_: Exception) { false }
    }

    private fun saveCookies(ctx: Context) {
        try {
            val cookieStr = sessionCookies.entries.joinToString("||") { "${it.key}=${it.value}" }
            ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE).edit()
                .putString("saved_cookies", cookieStr)
                .putString("saved_auth", capturedAuthHeader)
                .putString("saved_center", capturedJioCenterId)
                .apply()
        } catch (_: Throwable) {}
    }

    private fun loadCookies(ctx: Context) {
        try {
            val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            val cookieStr = prefs.getString("saved_cookies", "") ?: ""
            if (cookieStr.isNotEmpty()) cookieStr.split("||").forEach {
                val p = it.split("=", limit = 2)
                if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
            }
            if (capturedAuthHeader.isEmpty()) capturedAuthHeader = prefs.getString("saved_auth", "") ?: ""
            if (capturedJioCenterId.isEmpty()) capturedJioCenterId = prefs.getString("saved_center", "") ?: ""
        } catch (_: Throwable) {}
    }

    private fun toSortedJsonString(obj: JSONObject): String {
        val sorted = TreeMap<String, Any?>()
        obj.keys().forEach { key ->
            val v = obj.get(key)
            sorted[key] = when (v) {
                is JSONObject -> toSortedJsonString(v)
                is JSONArray -> (0 until v.length()).map { val item = v[it]; if (item is JSONObject) toSortedJsonString(item) else item }
                else -> if (v == JSONObject.NULL) null else v
            }
        }
        return sorted.entries.joinToString(",", "{", "}") { (k, v) ->
            val valStr = when (v) {
                null -> "null"
                is String -> "\"${v.replace("\\", "\\\\").replace("\"", "\\\"")}\""
                else -> v.toString()
            }
            "\"$k\":$valStr"
        }
    }

    private fun generateSignature(body: String): String = try {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(HMAC_SECRET.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        Base64.encodeToString(mac.doFinal(body.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    } catch (_: Exception) { "" }

    private fun httpPostNoSig(urlStr: String, body: String, extraHeaders: Map<String, String>): String {
        val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            doInput = true
            connectTimeout = 30000
            readTimeout = 30000
            setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "*/*")
            setRequestProperty("Origin", "https://jpw.jio.com")
            setRequestProperty("Referer", "https://jpw.jio.com/retailv1/workOrderV3/reached")
        }
        val cookieStr = sessionCookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
        if (cookieStr.isNotEmpty()) conn.setRequestProperty("Cookie", cookieStr)
        if (capturedAuthHeader.isNotEmpty() && !extraHeaders.containsKey("Authorization")) conn.setRequestProperty("Authorization", capturedAuthHeader)
        if (capturedJioCenterId.isNotEmpty() && !extraHeaders.containsKey("X-JioCenterId")) conn.setRequestProperty("X-JioCenterId", capturedJioCenterId)

        extraHeaders.forEach { (k, v) -> conn.setRequestProperty(k, v) }

        OutputStreamWriter(conn.outputStream).use { it.write(body) }
        val responseBody = try { conn.inputStream.bufferedReader().readText() } catch (_: Exception) { conn.errorStream?.bufferedReader()?.readText() ?: "" }
        conn.headerFields?.forEach { (key, values) ->
            if (key != null && key.equals("Set-Cookie", ignoreCase = true)) values.forEach {
                val p = it.split(";")[0].split("=", limit = 2)
                if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
            }
        }
        conn.disconnect()
        return responseBody
    }

    private fun showToast(ctx: Context, msg: String) {
        try { Handler(Looper.getMainLooper()).post { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show() } } catch (_: Throwable) {}
    }

    private fun dp(ctx: Context, v: Int): Int = (v * ctx.resources.displayMetrics.density).toInt()
    private fun makeRedGradient(ctx: Context) = android.graphics.drawable.GradientDrawable(
        android.graphics.drawable.GradientDrawable.Orientation.TL_BR,
        intArrayOf(0xFFe60012.toInt(), 0xFFff3a44.toInt())
    ).apply { cornerRadius = dp(ctx, 28).toFloat() }

    private fun bypassSignatureAndIntegrity(cl: ClassLoader) {
        try { XposedHelpers.findAndHookMethod("com.jio.jpss.utils.CommonUtility", cl, "checkAPKInstallationValidation", Context::class.java, XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
        try { XposedHelpers.findAndHookMethod("com.jio.jpss.utils.CommonUtility", cl, "checkIfAppCloned", Context::class.java, String::class.java, XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
        try { XposedHelpers.findAndHookMethod("com.jio.jpss.AppSignatureHelper", cl, "getAppSignatures", XC_MethodReplacement.returnConstant(null)) } catch (_: Throwable) {}
        try { XposedHelpers.findAndHookMethod("com.jio.jpss.utils.CommonUtility", cl, "getSigningCertSha256", Context::class.java, XC_MethodReplacement.returnConstant("dba24e5c252891027c96b8d21b1659dad47219f5d4e0be0bd898640509ca380c")) } catch (_: Throwable) {}
        try { XposedHelpers.findClass("com.jio.jpss.asynctask.ValidateAppCheckAsyncTask", cl).declaredMethods.forEach { if (it.name == "doInBackground" || it.name == "onPostExecute") XposedBridge.hookMethod(it, XC_MethodReplacement.returnConstant(null)) } } catch (_: Throwable) {}
    }

    private fun bypassSimVerification(cl: ClassLoader) {
        try {
            val tm = Class.forName("android.telephony.TelephonyManager")
            for (mName in listOf("getSubscriberId", "getLine1Number", "getSimSerialNumber", "getDeviceId", "getImei", "getMeid", "getSimOperator", "getSimOperatorName", "getNetworkOperator", "getNetworkOperatorName", "getSimCountryIso", "getNetworkCountryIso"))
                tm.declaredMethods.filter { it.name == mName }.forEach { try { XposedBridge.hookMethod(it, XC_MethodReplacement.returnConstant("")) } catch (_: Throwable) {} }
            for (mName in listOf("hasIccCard", "isNetworkRoaming", "isDataEnabled"))
                tm.declaredMethods.filter { it.name == mName }.forEach { try { XposedBridge.hookMethod(it, XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {} }
            tm.declaredMethods.filter { it.name == "getSimState" }.forEach { try { XposedBridge.hookMethod(it, XC_MethodReplacement.returnConstant(5)) } catch (_: Throwable) {} }
        } catch (_: Throwable) {}
    }

    private fun hookHttpCookieCapture(cl: ClassLoader) {
        try {
            val reqBuilderCls = XposedHelpers.findClass("okhttp3.Request\$Builder", cl)
            for (mName in listOf("addHeader", "header")) {
                XposedHelpers.findAndHookMethod(reqBuilderCls, mName, String::class.java, String::class.java, object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) { captureHeader(p.args[0] as? String ?: return, p.args[1] as? String ?: return) }
                })
            }
        } catch (_: Throwable) {}
        try {
            XposedBridge.hookAllMethods(java.net.URLConnection::class.java, "setRequestProperty", object : XC_MethodHook() {
                override fun beforeHookedMethod(p: MethodHookParam) { captureHeader(p.args.getOrNull(0) as? String ?: return, p.args.getOrNull(1) as? String ?: return) }
            })
        } catch (_: Throwable) {}
        try {
            XposedBridge.hookAllMethods(java.net.URLConnection::class.java, "getHeaderField", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    val conn = p.thisObject as? java.net.HttpURLConnection ?: return
                    if (conn.url?.toString()?.contains("jpw.jio.com") != true) return
                    if ((p.args.getOrNull(0) as? String)?.equals("Set-Cookie", ignoreCase = true) == true) {
                        val parts = (p.result as? String ?: return).split(";")[0].split("=", limit = 2)
                        if (parts.size == 2) sessionCookies[parts[0].trim()] = parts[1].trim()
                    }
                }
            })
        } catch (_: Throwable) {}
        try {
            XposedBridge.hookAllMethods(XposedHelpers.findClass("okhttp3.CookieJar", cl), "saveFromResponse", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    @Suppress("UNCHECKED_CAST")
                    (p.args[1] as? List<Any> ?: return).forEach {
                        val parts = it.toString().split(";")[0].split("=", limit = 2)
                        if (parts.size == 2) sessionCookies[parts[0].trim()] = parts[1].trim()
                    }
                }
            })
        } catch (_: Throwable) {}
    }

    private fun captureHeader(name: String, value: String) {
        if (name.equals("Cookie", ignoreCase = true)) value.split(";").forEach {
            val p = it.split("=", limit = 2)
            if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
        }
        else if (name.equals("Authorization", ignoreCase = true) && value.isNotEmpty()) capturedAuthHeader = value
        else if (name.equals("X-JioCenterId", ignoreCase = true) && value.isNotEmpty()) capturedJioCenterId = value
    }

        private fun registerBroadcastTrigger(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(mainCls, "onCreate", Bundle::class.java, object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    val ctx = (p.thisObject as Activity).applicationContext
                    val receiver = object : BroadcastReceiver() {
                        override fun onReceive(context: Context?, intent: Intent?) {
                            val techId = intent?.getStringExtra("techId") ?: return
                            val password = intent?.getStringExtra("password") ?: return
                            sessionCookies.clear()
                            ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE).edit()
                                .putString("technician_id", techId)
                                .putString("password", password)
                                .apply()
                            Thread { autoReach(ctx) }.start()
                        }
                    }
                    val filter = IntentFilter("com.jpwreach.TRIGGER_REACH")
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                        ctx.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
                    } else {
                        ctx.registerReceiver(receiver, filter)
                    }
                                }
            })
        } catch (_: Throwable) {}
    }
}
// END_OF_FILE
