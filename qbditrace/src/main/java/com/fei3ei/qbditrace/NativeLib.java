package com.fei3ei.qbditrace;

public class NativeLib {

    // Used to load the 'qbditrace' library on application startup.
    static {
        System.loadLibrary("qbditrace");
    }

    /**
     * A native method that is implemented by the 'qbditrace' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}