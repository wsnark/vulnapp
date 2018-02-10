package ru.defcon_nn.vulnapp;
import android.util.Log;

import java.net.URISyntaxException;

import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.client.SocketIOException;
import io.socket.emitter.Emitter;


public class SocketIoConnection {

    private static String TAG = "SocketIoConnection";

    public interface SimpleListener {
        void onConnected();
        void onDisconnected();
        void onError();
        void onMessage(String msg);
    }

    private Socket mSocket;
    private boolean isDisconnecting = false;

    SocketIoConnection(String uri, String username, String password,
                              final SimpleListener listener) {
        Log.d(TAG, "constructor");
        try {
            IO.Options options = new IO.Options();
            //options.secure = true;
            options.forceNew = true;
            options.reconnection = false;
            options.timeout = 15000;
            options.query = "username=" + username + "&password=" + password;
            options.port = 3000;

            mSocket = IO.socket(uri, options);

            mSocket.on(Socket.EVENT_CONNECT, new Emitter.Listener() {
                @Override
                public void call(Object... args) {
                    Log.d(TAG, "onConnected");
                    listener.onConnected();
                }
            }).on(Socket.EVENT_CONNECT_ERROR, new Emitter.Listener() {
                @Override
                public void call(Object... args) {
                    String err;
                    if (args.length == 0) {
                        err = "Unknown connection error";
                    } else if (args[0] instanceof SocketIOException) {
                        SocketIOException ex = (SocketIOException)args[0];
                        err = ex + " cause: " + ex.getCause();
                    } else {
                        err = args[0].toString();
                    }

                    Log.e(TAG, "onConnectError: " + err);
                    listener.onError();
                }
            }).on(Socket.EVENT_ERROR, new Emitter.Listener() {
                @Override
                public void call(Object... args) {
                    Log.e(TAG, "onError: " + args[0]);
                    listener.onError();
                }
            }).on(Socket.EVENT_DISCONNECT, new Emitter.Listener() {
                @Override
                public void call(Object... args) {
                    Log.d(TAG, "onDisconnect");
                    if (!isDisconnecting) { // if we're disconnecting, listener may be not available
                        listener.onDisconnected();
                    }
                }
            }).on(Socket.EVENT_MESSAGE, new Emitter.Listener() {
                @Override
                public void call(Object... args) {
                    Log.d(TAG, "onMessage");
                    listener.onMessage((String)args[0]);
                }
            });
        } catch (URISyntaxException e) {
            e.printStackTrace();
            listener.onError();
        }
    }

    void connect() {
        Log.d(TAG, "connect()");
        mSocket.connect();
    }

    void disconnect() {
        Log.d(TAG, "disconnect()");
        isDisconnecting = true;
        mSocket.disconnect();
        mSocket.close();
    }

    boolean isConnected() {
        return mSocket.connected();
    }
}

