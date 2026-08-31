package io.github.kennethchoinfosec.haven.util.inject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Minimal reader/writer for Android's binary XML (AXML, as emitted by AAPT2),
// used to patch an APK's AndroidManifest.xml on-device.
//
// Supported mutations:
//   * set <application android:name> to a given wrapper class;
//   * if the app had a custom application class, append a
//     <meta-data android:name="haven_inject_orig_app" android:value="..."/>
//     child so the wrapper can chain to the original Application.
//
// All other chunks are copied verbatim. If the manifest uses a styled string
// pool (extremely rare) or anything we cannot represent, patchManifest()
// throws IOException and the caller aborts the inject install cleanly.
//
// Coordinates: the 8-byte chunk header (type+headerSize+size) is stripped from
// every chunk, so "payload" offsets are chunk-relative minus 8. For string
// pool offsets, values in the file are relative to the string data section;
// the section sits at stringsStart from the chunk start.
public final class BinaryAXML {
    static final int RES_XML_TYPE = 0x0003;
    static final int RES_STRING_POOL_TYPE = 0x0001;
    static final int RES_START_NAMESPACE_TYPE = 0x0100;
    static final int RES_START_ELEMENT_TYPE = 0x0102;
    static final int RES_END_ELEMENT_TYPE = 0x0103;

    static final int UTF8_FLAG = 0x00000100;
    static final int STYLED_FLAG = 0x00000001;
    static final int TYPE_STRING = 0x03;

    public static final String ANDROID_NS_URI = "http://schemas.android.com/apk/res/android";
    public static final String ORIG_APP_META_KEY = "haven_inject_orig_app";

    static final class Chunk {
        final int type;
        final int headerSize;
        byte[] payload;

        Chunk(int type, int headerSize, byte[] payload) {
            this.type = type;
            this.headerSize = headerSize;
            this.payload = payload;
        }
    }

    static final class StringPool {
        boolean utf8;
        final List<String> strings = new ArrayList<>();
        final Map<String, Integer> firstIndex = new HashMap<>();

        String get(int index) {
            return strings.get(index);
        }

        int add(String s) {
            Integer i = firstIndex.get(s);
            if (i != null) return i;
            strings.add(s);
            firstIndex.put(s, strings.size() - 1);
            return strings.size() - 1;
        }
    }

    private final List<Chunk> mChunks = new ArrayList<>();
    private StringPool mPool;

    public static byte[] patchManifest(byte[] manifest, String wrapperClass, String originalAppClass)
            throws IOException {
        BinaryAXML xml = new BinaryAXML();
        xml.load(manifest);

        // Make sure every string we will reference exists in the pool.
        xml.mPool.add("name");
        xml.mPool.add(wrapperClass);
        if (originalAppClass != null && !originalAppClass.isEmpty()) {
            xml.mPool.add("meta-data");
            xml.mPool.add("value");
            xml.mPool.add(ORIG_APP_META_KEY);
            xml.mPool.add(originalAppClass);
        }

        Chunk app = xml.findApplicationElement();
        if (app == null) throw new IOException("no <application> element in manifest");

        int androidDecl = xml.findAndroidDeclarationIndex();
        if (androidDecl < 0) throw new IOException("no android namespace in manifest");

        if (!xml.setApplicationName(app, androidDecl, wrapperClass)) {
            throw new IOException("could not patch android:name on <application>");
        }

        if (originalAppClass != null && !originalAppClass.isEmpty()
                && !InjectorConstants.WRAPPER_CLASS.equals(originalAppClass)) {
            xml.appendMetaDataChild(app, androidDecl, originalAppClass);
        }

        return xml.serialize();
    }

    // Reads <application android:name> (the custom Application class, if any).
    public static String getApplicationName(byte[] manifest) throws IOException {
        BinaryAXML xml = new BinaryAXML();
        xml.load(manifest);
        int androidDecl = xml.findAndroidDeclarationIndex();
        Chunk app = xml.findApplicationElement();
        if (app == null || androidDecl < 0) return null;
        int count = readU16(app.payload, 12);
        int attrBase = readU16(app.payload, 8);
        int attrSize = readU16(app.payload, 10);
        if (attrSize < 20) return null;
        for (int i = 0; i < count; i++) {
            int o = attrBase + i * attrSize;
            if (readU32(app.payload, o) == androidDecl
                    && "name".equals(xml.mPool.get(readU32(app.payload, o + 4)))) {
                int stringIdx = readU32(app.payload, o + 16);
                String value = xml.mPool.get(stringIdx);
                if ("android.app.Application".equals(value) || value == null) {
                    return null; // default application class
                }
                return value;
            }
        }
        return null;
    }

    // ---- loading ----

    private void load(byte[] data) throws IOException {
        if (data.length < 8) throw new IOException("manifest too small");
        int type = readU16(data, 0);
        if (type != RES_XML_TYPE) throw new IOException("not a binary XML file");
        int fileSize = readU32(data, 4);
        int pos = 8;
        while (pos + 8 <= data.length && pos < fileSize) {
            int ctype = readU16(data, pos);
            int headerSize = readU16(data, pos + 2);
            int size = readU32(data, pos + 4);
            if (size < 8 || size < headerSize || pos + size > data.length) {
                throw new IOException("invalid chunk at " + pos);
            }
            byte[] payload = Arrays.copyOfRange(data, pos + 8, pos + size);
            Chunk chunk = new Chunk(ctype, headerSize, payload);
            if (ctype == RES_STRING_POOL_TYPE) {
                mPool = parsePool(payload);
            }
            mChunks.add(chunk);
            pos += size;
        }
        if (mPool == null) throw new IOException("no string pool in manifest");
    }

    private StringPool parsePool(byte[] d) throws IOException {
        if (d.length < 20) throw new IOException("bad string pool");
        int stringCount = readU32(d, 0);
        int styleCount = readU32(d, 4);
        int flags = readU32(d, 8);
        int stringsStart = readU32(d, 12); // from chunk start (chunk-relative)
        if ((flags & STYLED_FLAG) != 0 && styleCount > 0) {
            throw new IOException("styled string pool unsupported");
        }
        StringPool pool = new StringPool();
        pool.utf8 = (flags & UTF8_FLAG) != 0;
        // String i sits at chunk offset (stringsStart + offsets[i]).
        // In payload coordinates (payload = chunk start + 8):
        int payloadBase = stringsStart - 8;
        int offsetTablePos = 20;            // payload coord of offset table
        for (int i = 0; i < stringCount; i++) {
            int off = readU32(d, offsetTablePos + i * 4);
            int p = payloadBase + off;
            if (p < 0 || p >= d.length) throw new IOException("string offset out of range");
            pool.strings.add(pool.utf8 ? readUtf8String(d, p) : readUtf16String(d, p));
        }
        for (int i = 0; i < pool.strings.size(); i++) {
            pool.firstIndex.putIfAbsent(pool.strings.get(i), i);
        }
        return pool;
    }

    private String readUtf8String(byte[] d, int pos) {
        int[] len = readReaderLength(d, pos);         // UTF-16 length
        int[] len2 = readReaderLength(d, len[1]);     // UTF-8 byte length
        return new String(d, len2[1], len2[0], StandardCharsets.UTF_8);
    }

    private String readUtf16String(byte[] d, int pos) {
        int h = readU16(d, pos);
        int len;
        int p;
        if ((h & 0x8000) != 0) {
            len = ((h & 0x7FFF) << 16) | readU16(d, pos + 2);
            p = pos + 4;
        } else {
            len = h;
            p = pos + 2;
        }
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append((char) readU16(d, p + i * 2));
        }
        return sb.toString();
    }

    // ReaderLength: values < 0x80 are a single byte; otherwise a two-byte pair
    // 0x80|(v>>8), (v&0xff).
    private int[] readReaderLength(byte[] d, int pos) {
        int b = d[pos] & 0xFF;
        if ((b & 0x80) == 0) return new int[]{b, pos + 1};
        int v = ((b & 0x7F) << 8) | (d[pos + 1] & 0xFF);
        return new int[]{v, pos + 2};
    }

    // ---- mutation ----

    // Index (among namespace declarations, in document order) of android's URI.
    private int findAndroidDeclarationIndex() {
        int decl = 0;
        for (Chunk c : mChunks) {
            if (c.type == RES_START_NAMESPACE_TYPE) {
                int uri = readU32(c.payload, 4);
                if (ANDROID_NS_URI.equals(mPool.get(uri))) return decl;
                decl++;
            }
        }
        return -1;
    }

    private Chunk findApplicationElement() {
        for (Chunk c : mChunks) {
            if (c.type == RES_START_ELEMENT_TYPE) {
                int name = readU32(c.payload, 4);
                if ("application".equals(mPool.get(name))) return c;
            }
        }
        return null;
    }

    // StartElement payload layout (payload = chunk start + 8):
    //   +0  ns, +4  name, +8 attributeStart(u16), +10 attributeSize(u16),
    //   +12 attributeCount(u16), +14 idIndex(u16), +16 classIndex(u16),
    //   +18 styleIndex(u16), +20 attributes...
    // AAPT writes attributeStart = 20 (attrs begin at chunk+28 = payload+20).
    private boolean setApplicationName(Chunk app, int androidDecl, String wrapper) {
        int count = readU16(app.payload, 12);
        int attrBase = readU16(app.payload, 8);        // = 20 (relative to chunk+8)
        int attrSize = readU16(app.payload, 10);
        if (attrSize < 20) return false;
        int wrapperIdx = mPool.add(wrapper);
        for (int i = 0; i < count; i++) {
            int o = attrBase + i * attrSize;
            int ns = readU32(app.payload, o);
            int name = readU32(app.payload, o + 4);
            if (ns == androidDecl && "name".equals(mPool.get(name))) {
                int oldValueIdx = readU32(app.payload, o + 16); // typedValue.data
                if (readU32(app.payload, o + 8) == oldValueIdx) {
                    app.payload = replaceInt(app.payload, o + 8, wrapperIdx); // rawValue
                }
                app.payload = replaceInt(app.payload, o + 16, wrapperIdx);    // typedValue.data
                return true;
            }
        }
        return false;
    }

    private void appendMetaDataChild(Chunk app, int androidDecl, String originalAppName) {
        int metaNameIdx = mPool.add("meta-data");
        int nameAttrIdx = mPool.add("name");
        int valueAttrIdx = mPool.add("value");
        int keyIdx = mPool.add(ORIG_APP_META_KEY);
        int valueIdx = mPool.add(originalAppName);

        byte[] attrs = new byte[2 * 20];
        writeInt(attrs, 0, androidDecl);   // ns
        writeInt(attrs, 4, nameAttrIdx);
        writeInt(attrs, 8, keyIdx);        // raw value
        writeType(attrs, 12, keyIdx);
        writeInt(attrs, 20, androidDecl);
        writeInt(attrs, 24, valueAttrIdx);
        writeInt(attrs, 28, valueIdx);
        writeType(attrs, 32, valueIdx);

        byte[] startPayload = new byte[20 + attrs.length];
        writeInt(startPayload, 0, 0xFFFFFFFF); // ns: none
        writeInt(startPayload, 4, metaNameIdx);
        writeShort(startPayload, 8, 20);   // attributeStart
        writeShort(startPayload, 10, 20);  // attributeSize
        writeShort(startPayload, 12, 2);   // attributeCount
        writeShort(startPayload, 14, 0);   // idIndex
        writeShort(startPayload, 16, 0);   // classIndex
        writeShort(startPayload, 18, 0);   // styleIndex
        System.arraycopy(attrs, 0, startPayload, 20, attrs.length);
        Chunk startChunk = new Chunk(RES_START_ELEMENT_TYPE, 16, startPayload);

        byte[] endPayload = new byte[8];
        writeInt(endPayload, 0, 0xFFFFFFFF);
        writeInt(endPayload, 4, metaNameIdx);
        Chunk endChunk = new Chunk(RES_END_ELEMENT_TYPE, 16, endPayload);

        List<Chunk> rebuilt = new ArrayList<>(mChunks.size() + 2);
        for (Chunk c : mChunks) {
            rebuilt.add(c);
            if (c == app) {
                rebuilt.add(startChunk);
                rebuilt.add(endChunk);
            }
        }
        mChunks.clear();
        mChunks.addAll(rebuilt);
    }

    // ---- serialization ----

    private byte[] serialize() throws IOException {
        Chunk poolChunk = rebuildPoolChunk();
        // Replace the pool chunk in place of the original.
        for (int i = 0; i < mChunks.size(); i++) {
            if (mChunks.get(i).type == RES_STRING_POOL_TYPE) {
                mChunks.set(i, poolChunk);
                break;
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        writeShort(out, RES_XML_TYPE);
        writeShort(out, 8);
        for (Chunk c : mChunks) {
            writeShort(out, c.type);
            writeShort(out, c.headerSize);
            writeInt(out, c.headerSize + c.payload.length);
            out.write(c.payload, 0, c.payload.length);
        }
        byte[] result = out.toByteArray();
        writeInt(result, 4, result.length);
        return result;
    }

    private Chunk rebuildPoolChunk() {
        List<String> strings = mPool.strings;
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int[] offsets = new int[strings.size()];
        for (int i = 0; i < strings.size(); i++) {
            offsets[i] = data.size();
            byte[] enc = encodeString(strings.get(i), mPool.utf8);
            data.write(enc, 0, enc.length);
            while ((data.size() & 3) != 0) data.write(0);
        }

        int stringCount = strings.size();
        int flags = mPool.utf8 ? UTF8_FLAG : 0;
        int headerSize = 28;
        int stringsStart = headerSize + 4 * stringCount; // offset table size
        byte[] payload = new byte[28 + 4 * stringCount + data.size() - 8];
        writeInt(payload, 0, stringCount);
        writeInt(payload, 4, 0); // styleCount
        writeInt(payload, 8, flags);
        writeInt(payload, 12, stringsStart);
        writeInt(payload, 16, 0); // stylesStart
        for (int i = 0; i < offsets.length; i++) {
            writeInt(payload, 20 + i * 4, offsets[i]);
        }
        System.arraycopy(data.toByteArray(), 0, payload, 20 + offsets.length * 4, data.size());
        return new Chunk(RES_STRING_POOL_TYPE, headerSize, payload);
    }

    private byte[] encodeString(String s, boolean utf8) {
        if (utf8) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(encodeReaderLength(s.length())); // UTF-16 unit count first
            o.write(encodeReaderLength(b.length));   // then byte count
            o.write(b, 0, b.length);
            o.write(0);
            return o.toByteArray();
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int len = s.length();
        if (len < 0x8000) {
            o.write(len & 0xFF);
            o.write((len >> 8) & 0xFF);
        } else {
            // Long UTF-16 string: u16[0] = 0x8000 | (len >> 16), u16[1] = len & 0xFFFF
            o.write((len >> 16) & 0xFF);
            o.write(0x80 | ((len >> 24) & 0x7F));
            o.write(len & 0xFF);
            o.write((len >> 8) & 0xFF);
        }
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            o.write(c & 0xFF);
            o.write((c >> 8) & 0xFF);
        }
        o.write(0);
        o.write(0);
        return o.toByteArray();
    }

    private byte[] encodeReaderLength(int v) {
        if (v < 0x80) return new byte[]{(byte) v};
        return new byte[]{(byte) (0x80 | ((v >> 8) & 0x7F)), (byte) (v & 0xFF)};
    }

    // ---- helpers ----

    private static int readU16(byte[] d, int pos) {
        return (d[pos] & 0xFF) | ((d[pos + 1] & 0xFF) << 8);
    }

    private static int readU32(byte[] d, int pos) {
        return (d[pos] & 0xFF) | ((d[pos + 1] & 0xFF) << 8)
                | ((d[pos + 2] & 0xFF) << 16) | ((d[pos + 3] & 0xFF) << 24);
    }

    private static byte[] replaceInt(byte[] d, int pos, int value) {
        byte[] copy = d.clone();
        writeInt(copy, pos, value);
        return copy;
    }

    private static void writeInt(byte[] d, int pos, int v) {
        d[pos] = (byte) (v & 0xFF);
        d[pos + 1] = (byte) ((v >> 8) & 0xFF);
        d[pos + 2] = (byte) ((v >> 16) & 0xFF);
        d[pos + 3] = (byte) ((v >> 24) & 0xFF);
    }

    private static void writeShort(byte[] d, int pos, int v) {
        d[pos] = (byte) (v & 0xFF);
        d[pos + 1] = (byte) ((v >> 8) & 0xFF);
    }

    private static void writeType(byte[] d, int pos, int data) {
        writeShort(d, pos, 8);        // size
        d[pos + 2] = 0;               // res0
        d[pos + 3] = TYPE_STRING;     // dataType
        writeInt(d, pos + 4, data);   // data
    }

    private static void writeShort(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >> 8) & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >> 8) & 0xFF);
        o.write((v >> 16) & 0xFF);
        o.write((v >> 24) & 0xFF);
    }
}