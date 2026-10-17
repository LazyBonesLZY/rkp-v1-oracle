package rkp;
import java.lang.reflect.Method;
import android.os.IBinder;
import android.os.Parcel;

public class Stubs {
    // Use reflection-free approach: ServiceManager is @hide; call via reflection at runtime.
    static IBinder getService(String name) throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method m = sm.getMethod("getService", String.class);
        return (IBinder) m.invoke(null, name);
    }
}
