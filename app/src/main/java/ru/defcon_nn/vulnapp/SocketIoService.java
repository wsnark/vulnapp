package ru.defcon_nn.vulnapp;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;

public class SocketIoService extends Service {
    private final IBinder binder = new LocalBinder();
    private SocketIoConnection conn;

    public class LocalBinder extends Binder {
        SocketIoService getService() {
            return SocketIoService.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    public void connect(String uri, String login, String password,
                        SocketIoConnection.SimpleListener listener) {
        if (conn != null) {
            conn.disconnect();
        }
        conn = new SocketIoConnection(uri, login, password, listener);
        conn.connect();
    }

    public void disconnect() {
        if (conn != null) {
            conn.disconnect();
        }
        conn = null;
    }

}
