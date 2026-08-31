package io.github.kennethchoinfosec.haven.util.inject;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

// Repackages an APK for on-device install:
//   * reads AndroidManifest.xml from the original and patches <application android:name>
//     to the InjectorApp wrapper, recording the original application class,
//   * strips the original signature (META-INF signature files),
//   * adds the user-selected .so as lib/<abi>/libhaveninject.so,
//   * adds the bundled injector.dex as the next available classes<N>.dex,
//   * copies all remaining entries verbatim (preserves each entry's compression
//     method so resources.arsc / native libs stay byte-identical).
// The result is NOT signed yet; pass it to InjectSigner.
public final class ApkPatcher {
    private static final String TAG = "HavenInject";
    private static final int COPY_BUFFER = 256 * 1024;

    private ApkPatcher() {
    }

    public static File patch(Context context, File apk, InputStream injectedLib, String abi,
                             File outputDir) throws IOException {
        Log.i(TAG, "patching " + apk.getAbsolutePath() + " abi=" + abi);

        byte[] originalManifest = readEntry(apk, "AndroidManifest.xml");
        if (originalManifest == null) throw new IOException("no AndroidManifest.xml in APK");

        String origAppClass = BinaryAXML.getApplicationName(originalManifest);
        byte[] patchedManifest = BinaryAXML.patchManifest(originalManifest,
                InjectorConstants.WRAPPER_CLASS, origAppClass);
        Log.i(TAG, "original application class=" + origAppClass);

        byte[] injectorDex = rawResource(context, io.github.kennethchoinfosec.haven.R.raw.injector);
        if (injectorDex == null || injectorDex.length == 0) {
            throw new IOException("injector.dex resource is missing");
        }

        // Buffer the injected library once so the STORED entry can be written with
        // the exact CRC/size known up front.
        byte[] libData = readAll(injectedLib);
        if (libData.length == 0) throw new IOException("selected library is empty");

        File out = File.createTempFile("haven-injected-", ".apk", outputDir);
        try (ZipFile zip = new ZipFile(apk);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(out))) {

            int maxDex = 0;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();

                if (name.startsWith("META-INF/")) {
                    String up = name.toUpperCase();
                    if (up.endsWith(".SF") || up.endsWith(".RSA") || up.endsWith(".DSA")
                            || up.endsWith(".EC") || "META-INF/MANIFEST.MF".equals(name)) {
                        continue;
                    }
                }
                if ("AndroidManifest.xml".equals(name)) {
                    writeEntry(zos, name, patchedManifest, ZipEntry.DEFLATED);
                    continue;
                }
                if (name.startsWith(InjectorConstants.DEX_PREFIX)
                        && name.endsWith(InjectorConstants.DEX_SUFFIX)) {
                    String num = name.substring(InjectorConstants.DEX_PREFIX.length(),
                            name.length() - InjectorConstants.DEX_SUFFIX.length());
                    try {
                        int n = Integer.parseInt(num);
                        if (n > maxDex) maxDex = n;
                    } catch (NumberFormatException ignored) {
                    }
                }

                ZipEntry copy = new ZipEntry(name);
                copy.setMethod(e.getMethod());
                if (e.getTime() != -1) copy.setTime(e.getTime());
                try (InputStream in = zip.getInputStream(e)) {
                    zos.putNextEntry(copy);
                    byte[] buf = new byte[COPY_BUFFER];
                    int n;
                    while ((n = in.read(buf)) != -1) zos.write(buf, 0, n);
                }
                zos.closeEntry();
            }

            // Injected native library (STORED).
            ZipEntry libEntry = new ZipEntry("lib/" + abi + "/" + InjectorConstants.LIBRARY_FILE_NAME);
            libEntry.setMethod(ZipEntry.STORED);
            libEntry.setTime(0);
            libEntry.setSize(libData.length);
            libEntry.setCompressedSize(libData.length);
            CRC32 crc = new CRC32();
            crc.update(libData);
            libEntry.setCrc(crc.getValue());
            zos.putNextEntry(libEntry);
            zos.write(libData, 0, libData.length);
            zos.closeEntry();

            // Injected dex: use classes2.dex unless higher indexes already exist.
            int dexIndex = Math.max(maxDex + 1, 2);
            writeEntry(zos, InjectorConstants.DEX_PREFIX + dexIndex + InjectorConstants.DEX_SUFFIX,
                    injectorDex, ZipEntry.DEFLATED);
        } catch (IOException e) {
            out.delete();
            throw e;
        }
        Log.i(TAG, "patched apk written to " + out.getAbsolutePath());
        return out;
    }

    public static String getOriginalAppClass(File apk) throws IOException {
        byte[] manifest = readEntry(apk, "AndroidManifest.xml");
        if (manifest == null) return null;
        return BinaryAXML.getApplicationName(manifest);
    }

    private static void writeEntry(ZipOutputStream zos, String name, byte[] data, int method)
            throws IOException {
        ZipEntry e = new ZipEntry(name);
        e.setMethod(method);
        zos.putNextEntry(e);
        zos.write(data, 0, data.length);
        zos.closeEntry();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(1024, in.available()));
        byte[] buf = new byte[COPY_BUFFER];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static byte[] rawResource(Context context, int resId) {
        try (InputStream in = context.getResources().openRawResource(resId)) {
            return readAll(in);
        } catch (Throwable t) {
            Log.e(TAG, "could not read raw resource " + resId, t);
            return null;
        }
    }

    private static byte[] readEntry(File apk, String entryName) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry e = zip.getEntry(entryName);
            if (e == null) return null;
            try (InputStream in = zip.getInputStream(e)) {
                return readAll(in);
            }
        }
    }
}