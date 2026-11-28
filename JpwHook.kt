package com.jpwreach.lsposed

import android.app.Activity
import android.app.AlertDialog
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.location.Location
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebView
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLSocketFactory
import org.json.JSONArray
import org.json.JSONObject

class JpwHook : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "JpwHook"
        private const val TARGET_PKG = "com.jio.jpss"
        private fun log(s: String) = XposedBridge.log("[$TAG] $s")
    }

    private var appContextRef: Context? = null
    private var lastActivityRef: Activity? = null
    private var capturedAuthHeader: String = ""
    private var capturedJioCenterId: String = ""
    private val extraCapturedHeaders = ConcurrentHashMap<String, String>()
    private val sessionCookies = ConcurrentHashMap<String, String>()
    private val registeredReceivers = ConcurrentHashMap.newKeySet<String>()

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
        log("Loaded target package: ${lpparam.packageName} (process: ${lpparam.processName})")
        val cl = lpparam.classLoader
        bypassMockLocation()
        bypassDeveloperSettings()
        bypassRootBeer(cl)
        bypassAppSecurityModule(cl)
        hookSimAuthReactBridge(cl)
        hookAnyActivityResume(cl)
        bypassSimVerification(cl)
        bypassSignatureAndIntegrity(cl)
        hookHttpCookieCapture(cl)
        bypassCapturedImagesReview(cl)
    }

    private fun isReviewOrPhotoErrorText(raw: String?): Boolean {
        val t = raw?.trim()?.lowercase().orEmpty()
        if (t.isEmpty()) return false
        return t.contains("under review") ||
            t.contains("captured images") ||
            t.contains("photo error") ||
            t.contains("capture it again") ||
            t.contains("review photos") ||
            t.contains("wall mounted") ||
            t.contains("rejected") ||
            t.contains("upload again") ||
            t.contains("idu photo") ||
            t.contains("poe photo") ||
            t.contains("rmdu photo") ||
            t.contains("odu photo") ||
            t.contains("odu light") ||
            t.contains("serloop")
    }

    private fun bypassCapturedImagesReview(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                TextView::class.java,
                "setText",
                CharSequence::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val orig = param.args.getOrNull(0)?.toString()
                        if (isReviewOrPhotoErrorText(orig)) {
                            log("REVIEW_BYPASS(1-arg) hiding text: $orig")
                            param.args[0] = ""
                            (param.thisObject as? View)?.visibility = View.GONE
                        }
                    }
                }
            )
        } catch (t: Throwable) {
            log("REVIEW_BYPASS setText(1-arg) err: ${t.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                TextView::class.java,
                "setText",
                CharSequence::class.java,
                TextView.BufferType::class.java,
                Boolean::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val orig = param.args.getOrNull(0)?.toString()
                        if (isReviewOrPhotoErrorText(orig)) {
                            log("REVIEW_BYPASS(4-arg) hiding text: $orig")
                            param.args[0] = ""
                            (param.thisObject as? View)?.visibility = View.GONE
                        }
                    }
                }
            )
        } catch (t: Throwable) {
            log("REVIEW_BYPASS setText(4-arg) err: ${t.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                JSONObject::class.java,
                "optBoolean",
                String::class.java,
                Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = (param.args.getOrNull(0) as? String)?.lowercase() ?: return
                        if (
                            key.contains("underreview") ||
                            key.contains("under_review") ||
                            key.contains("inreview") ||
                            key.contains("photoerror") ||
                            key.contains("photo_error")
                        ) {
                            log("REVIEW_BYPASS forced $key -> false")
                            param.result = false
                        }
                    }
                }
            )
        } catch (t: Throwable) {
            log("REVIEW_BYPASS optBoolean err: ${t.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                Dialog::class.java,
                "show",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val dlg = param.thisObject as? Dialog ?: return
                        Handler(Looper.getMainLooper()).post {
                            try {
                                val decor = dlg.window?.decorView ?: return@post
                                hideReviewInTree(decor)
                                hideReviewInWebViews(decor)
                            } catch (_: Throwable) {}
                        }
                    }
                }
            )
        } catch (t: Throwable) {
            log("REVIEW_BYPASS Dialog.show err: ${t.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                Activity::class.java,
                "onResume",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val act = param.thisObject as? Activity ?: return
                        val decor = act.window?.decorView ?: return
                        decor.viewTreeObserver?.addOnGlobalLayoutListener {
                            hideReviewInTree(decor)
                            hideReviewInWebViews(decor)
                        }
                    }
                }
            )
        } catch (t: Throwable) {
            log("REVIEW_BYPASS layout listener err: ${t.message}")
        }
    }

    private fun hideReviewInTree(view: View?) {
        if (view == null) return
        if (view is TextView) {
            val txt = view.text?.toString()
            if (isReviewOrPhotoErrorText(txt)) {
                log("REVIEW_BYPASS tree hiding TextView: $txt")
                view.text = ""
                view.visibility = View.GONE
                (view.parent as? ViewGroup)?.let { parent ->
                    for (i in 0 until parent.childCount) {
                        val child = parent.getChildAt(i)
                        if (child is ProgressBar) {
                            child.visibility = View.GONE
                        }
                    }
                }
            }
        } else if (view is ViewGroup) {
            for (i in 0 until view.childCount) {
                hideReviewInTree(view.getChildAt(i))
            }
        }
    }

    private fun hideReviewInWebViews(root: View?) {
        if (root == null) return
        val webViews = mutableListOf<WebView>()
        fun collect(v: View?) {
            if (v == null) return
            if (v is WebView) {
                webViews.add(v)
            } else if (v is ViewGroup) {
                for (i in 0 until v.childCount) collect(v.getChildAt(i))
            }
        }
        collect(root)
        if (webViews.isEmpty()) return
        val js = """
            (function(){
                try{
                    var targets = ["under review","captured images","photo error","capture it again","review photos","wall mounted","rejected","upload again","idu photo","poe photo","rmdu photo","odu photo","odu light","serloop"];
                    var all = document.querySelectorAll('*');
                    for(var i=0;i<all.length;i++){
                        var el = all[i];
                        if(el.children.length === 0){
                            var t = (el.innerText || el.textContent || '').toLowerCase();
                            for(var j=0;j<targets.length;j++){
                                if(t.indexOf(targets[j]) !== -1){
                                    el.style.display = 'none';
                                    if(el.parentElement){ el.parentElement.style.display = 'none'; }
                                }
                            }
                        }
                    }
                }catch(e){}
            })();
        """.trimIndent()
        webViews.forEach { wv ->
            try { wv.evaluateJavascript(js, null) } catch (_: Throwable) {}
        }
    }

    private fun isFalseSimAuthStatus(resVal: String): Boolean {
        if (resVal.isEmpty()) return false
        return resVal.contains("\"status\"") &&
            (resVal.contains("\"status\" :\"false\"") || resVal.contains("\"status\":\"false\""))
    }

    private fun hookSimAuthReactBridge(cl: ClassLoader) {
        try {
            val reactUtilsClass = XposedHelpers.findClass("com.jio.jpss.AndroidReactUtils", cl)
            log("Found AndroidReactUtils for SIM Auth hook")

            // 1. startSimAuth(String userId, String cliList, Promise promise)
            reactUtilsClass.declaredMethods.filter { it.name == "startSimAuth" }.forEach { m ->
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val userId = p.args.getOrNull(0)
                        val cliList = p.args.getOrNull(1)
                        val promiseObj = p.args.getOrNull(2)
                        log("SIM_HOOK blocked startSimAuth -> userId=$userId | cliList=$cliList")
                        if (promiseObj != null) {
                            try {
                                XposedHelpers.callMethod(promiseObj, "resolve", """{"status" :"true"}""")
                                log("SIM_HOOK resolved startSimAuth Promise with true")
                            } catch (t: Throwable) {
                                log("SIM_HOOK startSimAuth promise err: ${t.message}")
                            }
                        }
                        p.result = null
                    }
                })
            }

            // 2. startSMSListener(...) -> block SMS retriever / OTP send
            reactUtilsClass.declaredMethods.filter { it.name == "startSMSListener" }.forEach { m ->
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        log("SIM_HOOK blocked startSMSListener")
                        p.result = null
                    }
                })
            }

            // 3. getSimAuthStatus(String json, Promise promise) -> sirf explicit false status ko true karein
            val hookedPromiseClasses = ConcurrentHashMap.newKeySet<Class<*>>()
            reactUtilsClass.declaredMethods.filter { it.name == "getSimAuthStatus" }.forEach { m ->
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val arg0 = p.args.getOrNull(0)
                        val promiseObj = p.args.getOrNull(1)
                        log("SIM_HOOK getSimAuthStatus called -> arg0=$arg0 | promise=${promiseObj?.javaClass?.name}")
                        if (promiseObj != null && hookedPromiseClasses.add(promiseObj.javaClass)) {
                            try {
                                XposedBridge.hookAllMethods(promiseObj.javaClass, "resolve", object : XC_MethodHook() {
                                    override fun beforeHookedMethod(rp: MethodHookParam) {
                                        val firstArg = rp.args.firstOrNull() ?: return
                                        val resVal = firstArg.toString()
                                        log("SIM_HOOK getSimAuthStatus resolve -> ${resVal.take(160)}")
                                        if (isFalseSimAuthStatus(resVal)) {
                                            rp.args[0] = """{"status" :"true"}"""
                                            log("SIM_HOOK forced false getSimAuthStatus resolve to true")
                                        }
                                    }
                                })
                            } catch (t: Throwable) {
                                log("SIM_HOOK promise hook err: ${t.message}")
                            }
                        }
                    }
                })
            }

            // 4. verifyOtpResponse(String response, Context ctx, Promise promise)
            reactUtilsClass.declaredMethods.filter { it.name == "verifyOtpResponse" }.forEach { m ->
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val rawResp = p.args.getOrNull(0)?.toString() ?: ""
                        log("SIM_HOOK verifyOtpResponse -> ${rawResp.take(200)}")
                    }
                })
            }
        } catch (t: Throwable) {
            log("hookSimAuthReactBridge err: ${t.message}")
        }
    }

    private fun hookAnyActivityResume(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                Activity::class.java,
                "onResume",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        val activity = p.thisObject as? Activity ?: return
                        appContextRef = activity.applicationContext
                        lastActivityRef = activity
                        log("Activity resumed: ${activity.javaClass.name}")
                        addFab(activity)
                        ensureBroadcastReceiver(activity.applicationContext)
                    }
                }
            )
            log("Hooked Activity.onResume successfully")
        } catch (t: Throwable) {
            log("Failed to hook Activity.onResume: ${t.message}")
        }
    }

    private fun ensureBroadcastReceiver(appCtx: Context?) {
        if (appCtx == null) return
        val key = appCtx.packageName
        if (!registeredReceivers.add(key)) return
        try {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    val techId = intent?.getStringExtra("techId") ?: return
                    val password = intent?.getStringExtra("password") ?: return
                    log("Broadcast received for techId=$techId")
                    sessionCookies.clear()
                    appCtx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE).edit()
                        .putString("technician_id", techId)
                        .putString("password", password)
                        .apply()
                    Thread { autoReach(appCtx) }.start()
                }
            }
            val filter = IntentFilter("com.jpwreach.TRIGGER_REACH")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appCtx.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                appCtx.registerReceiver(receiver, filter)
            }
            log("BroadcastReceiver registered")
        } catch (t: Throwable) {
            registeredReceivers.remove(key)
            log("BroadcastReceiver error: ${t.message}")
        }
    }

    private fun extractWebViewCookies() {
        try {
            val cm = CookieManager.getInstance()
            val rawCookies = cm.getCookie("https://jpw.jio.com") ?: ""
            if (rawCookies.isNotEmpty()) {
                log("WebView raw cookies -> ${rawCookies.take(220)}")
                rawCookies.split(";").forEach {
                    val p = it.split("=", limit = 2)
                    if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
                }
            }
        } catch (t: Throwable) {
            log("extractWebViewCookies error: ${t.message}")
        }
    }

    private fun dumpAppPrefs(ctx: Context) {
        try {
            val prefsDir = File(ctx.applicationInfo.dataDir, "shared_prefs")
            val files = prefsDir.listFiles()?.filter { it.extension == "xml" } ?: emptyList()
            log("Prefs files (${files.size}): ${files.map { it.nameWithoutExtension }}")
            for (f in files) {
                val name = f.nameWithoutExtension
                if (name == PREF_NAME) continue
                val map = ctx.getSharedPreferences(name, Context.MODE_PRIVATE).all
                if (map.isEmpty()) continue
                val interesting = map.entries.joinToString(", ") { (k, v) ->
                    val safeVal = if (k.contains("pass", true) || k.contains("pwd", true) || k.contains("otp", true) || k.contains("pin", true)) {
                        "***"
                    } else {
                        v.toString().take(80)
                    }
                    "$k=$safeVal"
                }
                log("SP[$name] -> $interesting")
            }
        } catch (t: Throwable) {
            log("dumpAppPrefs err: ${t.message}")
        }
    }

    private fun dumpDatabasesAndStorage(ctx: Context, act: Activity?) {
        try {
            val dbs = ctx.databaseList()?.toList() ?: emptyList()
            log("DBs (${dbs.size}): $dbs")
        } catch (t: Throwable) {
            log("databaseList err: ${t.message}")
        }

        val targetAct = act ?: lastActivityRef
        if (targetAct != null) {
            Handler(Looper.getMainLooper()).post {
                try {
                    val webViews = mutableListOf<WebView>()
                    fun findWebViews(v: View?) {
                        if (v == null) return
                        if (v is WebView) {
                            webViews.add(v)
                        } else if (v is ViewGroup) {
                            for (i in 0 until v.childCount) findWebViews(v.getChildAt(i))
                        }
                    }
                    findWebViews(targetAct.window?.decorView)
                    log("Found WebViews: ${webViews.size}")
                    webViews.forEachIndexed { idx, wv ->
                        val js = "(function(){try{var ls={};for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);ls[k]=String(localStorage.getItem(k)).slice(0,80);}return JSON.stringify({url:location.href,lsKeys:Object.keys(ls),ls:ls});}catch(e){return 'err:'+e;}})()"
                        wv.evaluateJavascript(js) { res ->
                            log("LS[$idx] -> ${res?.take(300)}")
                        }
                    }
                } catch (t: Throwable) {
                    log("WebView LS dump err: ${t.message}")
                }
            }
        }
    }

    private fun bypassMockLocation() {
        try { XposedHelpers.findAndHookMethod(Location::class.java, "isFromMockProvider", XC_MethodReplacement.returnConstant(false)) } catch (t: Throwable) { log("isFromMockProvider: ${t.message}") }
        try { XposedHelpers.findAndHookMethod(Location::class.java, "isMock", XC_MethodReplacement.returnConstant(false)) } catch (t: Throwable) { log("isMock: ${t.message}") }
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
                    if (m.returnType == Boolean::class.javaPrimitiveType) {
                        try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)) } catch (_: Throwable) {}
                    }
                }
            } catch (t: Throwable) {
                log("RootBeer class not found ($clsName): ${t.message}")
            }
        }
    }

    private fun bypassAppSecurityModule(cl: ClassLoader) {
        val kw = listOf(
            "isRoot", "checkRoot", "isMock", "checkMock",
            "isDevelop", "checkDevelop", "isEmulator", "checkEmulator",
            "isDebugger", "checkDebugger"
        )
        for (clsName in listOf("com.jio.jpss.AppSecurityModule", "com.jio.jpss.AppSecurityModule\$Companion")) {
            try {
                val clazz = XposedHelpers.findClass(clsName, cl)
                log("Found class: $clsName")
                clazz.declaredMethods.forEach { m ->
                    if (kw.none { m.name.contains(it, ignoreCase = true) }) return@forEach
                    try {
                        val rep = when (m.returnType) {
                            Boolean::class.javaPrimitiveType -> XC_MethodReplacement.returnConstant(false)
                            Int::class.javaPrimitiveType -> XC_MethodReplacement.returnConstant(0)
                            String::class.java -> XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, rep)
                        log("Hooked AppSecurityModule method: ${m.name}")
                    } catch (hookErr: Throwable) {
                        log("Hook err on ${m.name}: ${hookErr.message}")
                    }
                }
            } catch (t: Throwable) {
                log("AppSecurityModule not found ($clsName): ${t.message}")
            }
        }
    }

    private fun addFab(activity: Activity) {
        try {
            activity.window?.decorView?.post {
                val root = activity.findViewById<FrameLayout>(android.R.id.content)
                if (root == null || root.findViewWithTag<View>("jpw_auto_reach_fab") != null) return@post
                val ctx = activity
                val fab = Button(ctx).apply {
                    text = "⚡ AUTO-REACH"
                    setTextColor(Color.WHITE)
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
                log("FAB added on ${activity.javaClass.simpleName}")
            }
        } catch (t: Throwable) {
            log("addFab error: ${t.message}")
        }
    }

    private fun onAutoReachClicked(ctx: Context) {
        try {
            appContextRef = ctx.applicationContext
            log("onAutoReachClicked entered | ctx=${ctx.javaClass.name} | isActivity=${ctx is Activity}")
            extractWebViewCookies()
            loadCookies(ctx)
            dumpAppPrefs(ctx.applicationContext)
            dumpDatabasesAndStorage(ctx.applicationContext, ctx as? Activity)

            val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            val savedPass = prefs.getString("password", "") ?: ""
            val savedTechId = prefs.getString("technician_id", "") ?: ""

            val targetActivity = ctx as? Activity
            if (targetActivity != null && !targetActivity.isFinishing && !targetActivity.isDestroyed) {
                val lp = LinearLayout(targetActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(48, 24, 48, 16)
                }
                val techIdField = EditText(targetActivity).apply {
                    hint = "Enter Technician ID"
                    if (savedTechId.isNotEmpty()) setText(savedTechId)
                }
                val passField = EditText(targetActivity).apply {
                    hint = "Enter JPW password"
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    if (savedPass.isNotEmpty()) setText(savedPass)
                }
                lp.addView(techIdField)
                lp.addView(passField)

                AlertDialog.Builder(targetActivity)
                    .setTitle("Login Required")
                    .setMessage("Enter Technician ID and JPW password:")
                    .setView(lp)
                    .setNegativeButton("CANCEL", null)
                    .setPositiveButton("SAVE & RUN") { _, _ ->
                        val tid = techIdField.text.toString().trim()
                        val pwd = passField.text.toString().trim()
                        if (tid.isNotEmpty()) {
                            prefs.edit()
                                .putString("technician_id", tid)
                                .putString("password", pwd)
                                .apply()

                            Thread {
                                Handler(Looper.getMainLooper()).post { extractWebViewCookies() }
                                Thread.sleep(200)
                                loadCookies(ctx)

                                val hasExistingSession = sessionCookies.isNotEmpty() || capturedAuthHeader.isNotEmpty()
                                if (hasExistingSession) {
                                    log("Using existing live/saved session; skipping doLogin")
                                    autoReach(ctx)
                                } else if (pwd.isNotEmpty() && doLogin(ctx, tid, pwd)) {
                                    autoReach(ctx)
                                } else {
                                    showToast(ctx, "No session — login failed or missing. Check credentials.")
                                }
                            }.start()
                        } else {
                            showToast(ctx, "Enter Technician ID")
                        }
                    }
                    .show()
            } else {
                log("No valid Activity context to show dialog; running autoReach directly")
                Thread { autoReach(ctx) }.start()
            }
        } catch (t: Throwable) {
            log("onAutoReachClicked error: ${t.message}")
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

        val effectiveAuth = when {
            capturedAuthHeader.isNotEmpty() -> capturedAuthHeader
            sessionCookies["authToken"]?.isNotEmpty() == true -> sessionCookies["authToken"]!!
            else -> ""
        }

        log("DEBUG autoReach -> techId='$techId' | center='$jioCenterId' | cookies=${sessionCookies.keys} | authPresent=${effectiveAuth.isNotEmpty()}")

        if (sessionCookies.isEmpty() && effectiveAuth.isEmpty() && techId.isNotEmpty()) {
            val techPass = prefs.getString("password", "") ?: ""
            if (techPass.isNotEmpty()) doLogin(ctx, techId, techPass)
        }
        if (sessionCookies.isEmpty() && effectiveAuth.isEmpty()) {
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
        val woBodySorted = toSortedJsonString(woPayload)
        val woHeaders = mutableMapOf(
            "Referer" to "https://jpw.jio.com/v1/workOrderListV3",
            "X-Signature" to generateSignature(woBodySorted)
        )
        if (jioCenterId.isNotEmpty()) woHeaders["X-JioCenterId"] = jioCenterId
        if (effectiveAuth.isNotEmpty()) woHeaders["Authorization"] = effectiveAuth
        extraCapturedHeaders.forEach { (k, v) -> if (!woHeaders.containsKey(k)) woHeaders[k] = v }

        log("WO req headers -> $woHeaders | cookiesKeys=${sessionCookies.keys}")
        val woResult = httpPostNoSig(WO_URL, woBodySorted, woHeaders)
        log("WO raw -> result=$woResult")

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
            if (effectiveAuth.isNotEmpty()) reachHeaders["Authorization"] = effectiveAuth
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
            val bodyStr = toSortedJsonString(payload)
            val loginHeaders = mapOf(
                "Referer" to "https://jpw.jio.com/v1/OIDLOGIN",
                "X-Signature" to generateSignature(bodyStr)
            )
            val raw = httpPostNoSig(LOGIN_URL, bodyStr, loginHeaders)
            log("doLogin raw -> $raw")
            val json = JSONObject(raw)
            if (json.optBoolean("IsSuccessful", false)) {
                val sid = json.optString("sessionId", "")
                if (sid.isNotEmpty()) sessionCookies["JPSSSessionID"] = sid
                saveCookies(ctx)
                true
            } else false
        } catch (_: Exception) { false }
    }

    private fun saveCookies(ctx: Context?) {
        val targetCtx = ctx ?: appContextRef ?: return
        try {
            val cookieStr = sessionCookies.entries.joinToString("||") { "${it.key}=${it.value}" }
            targetCtx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE).edit()
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
            setRequestProperty("User-Agent", "okhttp/4.12.0")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json, text/plain, */*")
            setRequestProperty("Origin", "https://jpw.jio.com")
            setRequestProperty("Referer", "https://jpw.jio.com/retailv1/workOrderV3/reached")
            setRequestProperty("AppVersion", APP_VERSION)
            setRequestProperty("DeviceId", DEVICE_ID)
            setRequestProperty("Handset", "android")
        }
        val cookieStr = sessionCookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
        if (cookieStr.isNotEmpty()) conn.setRequestProperty("Cookie", cookieStr)
        if (capturedAuthHeader.isNotEmpty() && !extraHeaders.containsKey("Authorization")) conn.setRequestProperty("Authorization", capturedAuthHeader)
        if (capturedJioCenterId.isNotEmpty() && !extraHeaders.containsKey("X-JioCenterId")) conn.setRequestProperty("X-JioCenterId", capturedJioCenterId)

        extraHeaders.forEach { (k, v) -> conn.setRequestProperty(k, v) }

        OutputStreamWriter(conn.outputStream).use { it.write(body) }
        val code = try { conn.responseCode } catch (_: Exception) { -1 }
        val responseBody = try { conn.inputStream.bufferedReader().readText() } catch (_: Exception) { conn.errorStream?.bufferedReader()?.readText() ?: "" }
        log("HTTP POST $urlStr -> code=$code | len=${responseBody.length}")
        conn.headerFields?.forEach { (key, values) ->
            if (key != null && key.equals("Set-Cookie", ignoreCase = true)) values.forEach {
                val p = it.split(";")[0].split("=", limit = 2)
                if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
            }
        }
        saveCookies(appContextRef)
        conn.disconnect()
        return responseBody
    }

    private fun showToast(ctx: Context, msg: String) {
        try { Handler(Looper.getMainLooper()).post { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show() } } catch (_: Throwable) {}
    }

    private fun dp(ctx: Context, v: Int): Int = (v * ctx.resources.displayMetrics.density).toInt()
    private fun makeRedGradient(ctx: Context) = GradientDrawable(
        GradientDrawable.Orientation.TL_BR,
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
            XposedBridge.hookAllMethods(URL::class.java, "openConnection", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    try {
                        val urlStr = (p.thisObject as? URL)?.toString() ?: return
                        if (urlStr.contains("jpw.jio.com")) {
                            log("URL.openConnection -> $urlStr")
                        }
                        if (urlStr.contains("SendSMSForSimAuth", ignoreCase = true)) {
                            log("SIM_HOOK intercepted SendSMSForSimAuth connection")
                        }
                    } catch (t: Throwable) {
                        log("openConnection log err: ${t.message}")
                    }
                }
            })
            XposedBridge.hookAllMethods(HttpURLConnection::class.java, "getInputStream", object : XC_MethodHook() {
                override fun beforeHookedMethod(p: MethodHookParam) {
                    val urlStr = (p.thisObject as? HttpURLConnection)?.url?.toString() ?: ""
                    if (urlStr.contains("SendSMSForSimAuth", ignoreCase = true)) {
                        val fakeJson = """{"IsSuccessful":true,"RequestID":"bypassed","Message":"OK"}"""
                        p.result = ByteArrayInputStream(fakeJson.toByteArray(Charsets.UTF_8)) as InputStream
                        log("SIM_HOOK mocked SendSMSForSimAuth response")
                    }
                }
            })
        } catch (t: Throwable) {
            log("URL.openConnection hook err: ${t.message}")
        }

        try {
            XposedBridge.hookAllMethods(java.net.URLConnection::class.java, "setRequestProperty", object : XC_MethodHook() {
                override fun beforeHookedMethod(p: MethodHookParam) {
                    val k = p.args.getOrNull(0) as? String ?: return
                    val v = p.args.getOrNull(1) as? String ?: return
                    val connUrl = (p.thisObject as? java.net.URLConnection)?.url?.toString() ?: ""
                    if (connUrl.contains("jpw.jio.com")) {
                        log("URLConn Header -> $connUrl | $k=$v")
                    }
                    captureHeader(k, v)
                }
            })
        } catch (t: Throwable) {
            log("URLConnection setRequestProperty err: ${t.message}")
        }

        try {
            XposedBridge.hookAllMethods(java.net.URLConnection::class.java, "getHeaderField", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    val conn = p.thisObject as? HttpURLConnection ?: return
                    if (conn.url?.toString()?.contains("jpw.jio.com") != true) return
                    if ((p.args.getOrNull(0) as? String)?.equals("Set-Cookie", ignoreCase = true) == true) {
                        val parts = (p.result as? String ?: return).split(";")[0].split("=", limit = 2)
                        if (parts.size == 2) {
                            sessionCookies[parts[0].trim()] = parts[1].trim()
                            saveCookies(appContextRef)
                        }
                    }
                }
            })
        } catch (t: Throwable) {
            log("URLConnection getHeaderField err: ${t.message}")
        }

        try {
            XposedBridge.hookAllMethods(SSLSocketFactory::class.java, "createSocket", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    val host = p.args.getOrNull(0) as? String
                    if (host != null && host.contains("jpw.jio.com")) {
                        log("SSLSocket createSocket -> $host")
                    }
                }
            })
        } catch (t: Throwable) {
            log("SSLSocketFactory hook err: ${t.message}")
        }

        try {
            XposedBridge.hookAllMethods(WebView::class.java, "loadUrl", object : XC_MethodHook() {
                override fun beforeHookedMethod(p: MethodHookParam) {
                    val u = p.args.firstOrNull() as? String ?: return
                    if (u.contains("jpw.jio.com") || u.contains("workOrder", ignoreCase = true)) {
                        log("WebView.loadUrl -> ${u.take(160)}")
                    }
                }
            })
            XposedBridge.hookAllMethods(WebView::class.java, "evaluateJavascript", object : XC_MethodHook() {
                override fun beforeHookedMethod(p: MethodHookParam) {
                    val js = p.args.firstOrNull() as? String ?: return
                    if (js.contains("workOrder", ignoreCase = true) || js.contains("center", ignoreCase = true) || js.contains("token", ignoreCase = true)) {
                        log("WebView.evalJS -> ${js.take(120)}")
                    }
                }
            })
        } catch (t: Throwable) {
            log("WebView hook err: ${t.message}")
        }
    }

    private fun captureHeader(name: String, value: String) {
        if (name.equals("Cookie", ignoreCase = true)) {
            value.split(";").forEach {
                val p = it.split("=", limit = 2)
                if (p.size == 2) sessionCookies[p[0].trim()] = p[1].trim()
            }
            saveCookies(appContextRef)
        } else if (name.equals("Authorization", ignoreCase = true) && value.isNotEmpty()) {
            capturedAuthHeader = value
            saveCookies(appContextRef)
        } else if (name.equals("X-JioCenterId", ignoreCase = true) && value.isNotEmpty()) {
            capturedJioCenterId = value
            saveCookies(appContextRef)
        } else if (name.startsWith("X-", ignoreCase = true) && value.isNotEmpty()) {
            extraCapturedHeaders[name] = value
            if (name.contains("Sig", ignoreCase = true) || name.contains("Token", ignoreCase = true) || name.contains("Auth", ignoreCase = true)) {
                log("Captured header -> $name=${value.take(24)}...")
            }
        }
    }
}
