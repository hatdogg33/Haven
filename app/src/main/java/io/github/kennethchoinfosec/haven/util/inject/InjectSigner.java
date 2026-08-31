package io.github.kennethchoinfosec.haven.util.inject;

import android.content.Context;
import android.util.Log;

import com.android.apksig.ApkSigner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// Re-signs the patched (or plain) APK with the built-in Haven Inject key so the
// clone installs with a stable, reproducible signature. The original APK is used
// only as read-only input; results are written as new files.
public final class InjectSigner {
    private static final String TAG = "HavenInject";
    private static final String KEY_ALGORITHM = "RSA";

    private InjectSigner() {
    }

    public static File sign(Context context, File inputApk, File outputDir) throws Exception {
        return signApk(context, inputApk, new File(outputDir, "haven-signed-" + inputApk.getName()));
    }

    // Re-signs split APKs (unchanged content) so their signature matches the
    // re-signed base APK. Returns the signed copies.
    public static List<File> signSplits(Context context, List<String> splitPaths, File outputDir)
            throws Exception {
        List<File> result = new ArrayList<>();
        for (String path : splitPaths) {
            File src = new File(path);
            File dst = new File(outputDir, "haven-split-" + src.getName());
            signApk(context, src, dst);
            result.add(dst);
        }
        return result;
    }

    private static void signApk(Context context, File inputApk, File outputApk) throws Exception {
        SignerKeys keys = loadKeys(context);
        ApkSigner.SignerConfig signer = new ApkSigner.SignerConfig.Builder(
                "HavenInject", keys.privateKey, Collections.singletonList(keys.certificate))
                .build();
        Log.i(TAG, "signing " + inputApk.getName() + " -> " + outputApk.getName());
        new ApkSigner.Builder(Collections.singletonList(signer))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setMinSdkVersion(24)
                .setCreatedBy("Haven Inject")
                .build()
                .sign();
    }

    private static SignerKeys loadKeys(Context context) throws Exception {
        byte[] keyDer = rawResource(context, io.github.kennethchoinfosec.haven.R.raw.inject_key);
        byte[] certDer = rawResource(context, io.github.kennethchoinfosec.haven.R.raw.inject_cert);
        PrivateKey privateKey = KeyFactory.getInstance(KEY_ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(keyDer));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certDer));
        return new SignerKeys(privateKey, certificate);
    }

    private static byte[] rawResource(Context context, int resId) throws Exception {
        try (InputStream in = context.getResources().openRawResource(resId)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static final class SignerKeys {
        final PrivateKey privateKey;
        final X509Certificate certificate;

        SignerKeys(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }
}