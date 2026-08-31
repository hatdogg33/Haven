package io.github.kennethchoinfosec.haven.inject;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

// This class is compiled into its own dex ("injector.dex") and injected into
// a cloned APK at install time. ApkPatcher rewrites the clone's manifest so
// <application android:name> points here, which makes the framework instantiate
// this class on app startup.
//
// It must ONLY use APIs available at runtime on Android API 24+, and must NOT
// reference any other Haven class.
public class InjectorApp extends Application {

    private static final String TAG = "HavenInject";

    // The .so the user picked is renamed to libhaveninject.so inside the APK;
    // we load it with this fixed name on process start.
    private static final String LIBRARY_NAME = "haveninject";

    private Application mOriginal = null;

    // Loading from a static initializer fires before <clinit> of the target app
    // is allowed to run, i.e. as early as possible in the process.
    static {
        try {
            System.loadLibrary(LIBRARY_NAME);
            android.util.Log.i(TAG, "injected library loaded");
        } catch (Throwable t) {
            // The target app must still run even if the library cannot be loaded.
            android.util.Log.e(TAG, "failed to preload injected library", t);
        }
    }

    @Override
    public void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            System.loadLibrary(LIBRARY_NAME);
        } catch (Throwable t) {
            // Already loaded, or genuinely unavailable.
        }

        // Best-effort chaining to the original application class. ApkPatcher stores
        // the original <application android:name> in a meta-data entry so we can
        // reconstruct the real Application without breaking its initialization.
        try {
            ApplicationInfo ai = base.getPackageManager()
                    .getApplicationInfo(base.getPackageName(), PackageManager.GET_META_DATA);
            if (ai.metaData != null && ai.metaData.containsKey("haven_inject_orig_app")) {
                String orig = ai.metaData.getString("haven_inject_orig_app");
                if (orig != null && !orig.isEmpty()
                        && !InjectorApp.class.getName().equals(orig)) {
                    try {
                        Class<?> cls = Class.forName(orig);
                        Object instance = cls.newInstance();
                        if (instance instanceof Application) {
                            mOriginal = (Application) instance;
                            try {
                                // attachBaseContext is protected; call it reflectively
                                // so the original Application can bind its resources.
                                java.lang.reflect.Method attach =
                                        Application.class.getDeclaredMethod(
                                                "attachBaseContext", Context.class);
                                attach.setAccessible(true);
                                attach.invoke(mOriginal, base);
                            } catch (Throwable t) {
                                // Some frameworks forbid reflection into attachBaseContext
                            }
                        }
                    } catch (Throwable t) {
                        // Original class could not be instantiated; continue without it.
                    }
                }
            }
        } catch (Throwable t) {
            // Meta-data unreadable; continue without the original application.
        }
    }

    @Override
    public void onCreate() {
        // Give user code (patched later) an entry point that runs after the
        // injected library is definitely loaded.
        try {
            onInjectedLibraryLoaded();
        } catch (Throwable t) {
            // Never let injected code break the app.
        }
        if (mOriginal != null) {
            try {
                mOriginal.onCreate();
            } catch (Throwable t) {
                // Original application failed to initialize; keep going.
            }
        }
    }

    // Stub that modders can override in a patched copy of injector.dex.
    protected void onInjectedLibraryLoaded() {
    }
}