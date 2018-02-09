package ru.defcon_nn.vulnapp;
import android.util.Log;

import java.net.URISyntaxException;

import io.socket.client.IO;
import io.socket.client.Socket;


public class SocketIoConnection {

    private static String TAG = "SocketIoConnection";

    private Socket mSocket;
    public SocketIoConnection(String uri, String username, String password) {
        Log.d(TAG, "constructor");
        try {
            IO.Options options = new IO.Options();
            //options.secure = true;
            options.forceNew = false;
            options.timeout = 15000;
            options.query = "param=12345";
            options.port = 3000;

            mSocket = IO.socket(uri, options);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    public void connect() {
        Log.d(TAG, "connect()");
        mSocket.connect();
    }

    public void disconnect() {
        Log.d(TAG, "disconnect()");
        mSocket.disconnect();
        mSocket.close();
    }

    public boolean isConnected() {
        return mSocket.connected();
    }
}

