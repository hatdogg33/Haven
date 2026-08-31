package io.github.kennethchoinfosec.haven.util.inject;

// Constants shared by the on-device APK patcher and the injector dex builder.
public final class InjectorConstants {
    // Fully-qualified name of the wrapper Application inside injector.dex.
    public static final String WRAPPER_CLASS = "io.github.kennethchoinfosec.haven.inject.InjectorApp";

    // The user-selected library is renamed to this inside the APK; InjectorApp
    // calls System.loadLibrary("haveninject").
    public static final String LIBRARY_NAME = "haveninject";
    public static final String LIBRARY_FILE_NAME = "lib" + LIBRARY_NAME + ".so";

    // Meta-data key used to store the original application class name.
    public static final String ORIG_APP_META_KEY = "haven_inject_orig_app";

    // Inside the APK, the extra dex is named classes2.dex / classes3.dex ...
    public static final String DEX_PREFIX = "classes";
    public static final String DEX_SUFFIX = ".dex";

    private InjectorConstants() {
    }
}