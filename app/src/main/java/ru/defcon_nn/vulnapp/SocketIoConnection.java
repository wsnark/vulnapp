package ru.defcon_nn.vulnapp;

import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.client.SocketIOException;
import io.socket.emitter.Emitter;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.internal.tls.CertificateChainCleaner;


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

    static class TrustAnyTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static X509TrustManager getSystemTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        TrustManager[] trustManagers = tmf.getTrustManagers();
        return (X509TrustManager) trustManagers[0];
    }

    static class PinSubjectTrustManager implements X509TrustManager {
        X509TrustManager systemTrustManager;

        PinSubjectTrustManager() {
            try {
                systemTrustManager = getSystemTrustManager();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            systemTrustManager.checkServerTrusted(chain, authType);
            // VULN: no chain cleaning
            checkSubjPinning(chain); // VULN: wrong stuff pinned
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static class NoBasicConstraintsPinningTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // VULN: no basic constraints validation
            // VULN: no chain cleaning
            checkPinning(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static class DirtyPinningTrustManager implements X509TrustManager {
        X509TrustManager systemTrustManager;

        DirtyPinningTrustManager() {
            try {
                systemTrustManager = getSystemTrustManager();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            systemTrustManager.checkServerTrusted(chain, authType);
            checkPinning(chain); // VULN: no chain cleaning
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    // Vulnerable checkPinning: checks Subject instead of full cert or public key
    static void checkSubjPinning(X509Certificate[] chain) throws CertificateException {
        final String pinnedName = "CN=Intermediate Example Certificate, OU=Workshops, O=DC7831, L=Nizhniy Novgorod, ST=Nizhegorodskaya Obl, C=RU";
        //final String pinnedName = "MITM Workshop Cert, OU=Workshops, O=DC7831, L=Nizhniy Novgorod, ST=Nizhegorodskaya Obl, C=RU";
        final byte[] pinnedValue = { 46, 88, -41, 22, 10, -51, -11, 50, -91, -52,
                -115, 23, 45, -112, 20, 101, -94, 41, -101, -118, 1, -119, -32,
                -39, -18, -8, -128, -116, 105, -45, 28, 126 };
        try {
            boolean pinFound = false;
            for (X509Certificate x509cert : chain) {
                X500Principal certPrincipal = x509cert.getSubjectX500Principal();
                //name check
                String certName = certPrincipal.getName("RFC1779");
                Log.d(TAG, "Cert name: " + certName);
                if (pinnedName.equals(certName)) {
                    // found matching pinned cert, now check if the certs are the same
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(certPrincipal.getEncoded()); // VULN: Subject field is pinned instead of full cert or public key
                    byte[] dig = md.digest();
                    if (!Arrays.equals(dig, pinnedValue)) {
                        throw new CertificateException("Pinned certificate override detected, hash: " + Arrays.toString(dig));
                    }
                    pinFound = true;
                }
            }
            if (!pinFound) {
                throw new CertificateException("No pinned certificate!");
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CertificateException("No SHA-256 algo to check pinning!");
        }
    }

    // Valid check for pinning
    static void checkPinning(X509Certificate[] chain) throws CertificateException {
        final String pinnedName = "CN=Intermediate Example Certificate, OU=Workshops, O=DC7831, L=Nizhniy Novgorod, ST=Nizhegorodskaya Obl, C=RU";
        final byte[] pinnedValue = { -65, -54, -11, 30, 106, -96, 117, -5, 120, -128,
                -45, 99, -105, -84, -11, 98, -95, -125, 11, -97, -38, 35, -20, 110,
                -117, 104, -2, -33, 113, 80, -58, 58};
        try {
            boolean pinFound = false;
            for (X509Certificate x509cert : chain) {
                X500Principal certPrincipal = x509cert.getSubjectX500Principal();
                String certName = certPrincipal.getName("RFC1779");
                Log.d(TAG, "Cert name: " + certName);
                if (pinnedName.equals(certName)) {
                    // found matching pinned cert, now check if the certs are the same
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(x509cert.getEncoded()); // Good check -- full certificate is pinned
                    byte[] dig = md.digest();
                    if (!Arrays.equals(dig, pinnedValue)) {
                        throw new CertificateException("Pinned certificate override detected, hash: " + Arrays.toString(dig));
                    }
                    pinFound = true;
                }
            }
            if (!pinFound) {
                throw new CertificateException("No pinned certificate!");
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CertificateException("No SHA-256 algo to check pinning!");
        }
    }

    static class EmptyHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    static class WrongHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            Log.d(TAG, "Hostname: " + hostname + " PeerHost: " + session.getPeerHost());
            return (hostname != null) && hostname.equals(session.getPeerHost()); // VULN: getPeerHost() returns tainted data
        }
    }

    private static void init(X509TrustManager tm, HostnameVerifier hv) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{tm}, null);

        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .hostnameVerifier(hv)
                .sslSocketFactory(sslContext.getSocketFactory(), tm)
                .build();

        // default settings for all sockets
        IO.setDefaultOkHttpWebSocketFactory(okHttpClient);
        IO.setDefaultOkHttpCallFactory(okHttpClient);
    }

    //Peer certificate chain:
    // sha256/O7PuElke5LieOCkGNLeyLQ63sSjHrYGyOyzNtYWNUNM=: CN=MITM Workshop Cert,OU=Workshops,O=DC7831,L=Nizhniy Novgorod,ST=Nizhegorodskaya Obl,C=RU
    // sha256/wgCOdojGfXVSLvYJ8VQV2sLIJLIXu9TdLn509Y2sS70=: CN=Intermediate Example Certificate,OU=Workshops,O=DC7831,L=Nizhniy Novgorod,ST=Nizhegorodskaya Obl,C=RU
    // sha256/zytYLcplRvfGz0j7St+sAPK/IJgE9LUEXQ5iF6U8d9w=: CN=wsnark,OU=Workshops,O=DC7831,ST=Nizhegorodskaya Obl,C=RU

    private static void initGoodPinBadHostnameVerifier() {
        String hostname = "mitm.defcon-nn.ru";
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add(hostname, "sha256/wgCOdojGfXVSLvYJ8VQV2sLIJLIXu9TdLn509Y2sS70=")
                .build();
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .hostnameVerifier(new WrongHostnameVerifier())
                .build();
        // default settings for all sockets
        IO.setDefaultOkHttpWebSocketFactory(okHttpClient);
        IO.setDefaultOkHttpCallFactory(okHttpClient);
    }

    private static void initBestPractice() {
        String hostname = "mitm.defcon-nn.ru";
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add(hostname, "sha256/wgCOdojGfXVSLvYJ8VQV2sLIJLIXu9TdLn509Y2sS70=")
                .build();
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .build();
        // default settings for all sockets
        IO.setDefaultOkHttpWebSocketFactory(okHttpClient);
        IO.setDefaultOkHttpCallFactory(okHttpClient);
    }

    static {
        try {
            //init(new TrustAnyTrustManager(), new EmptyHostnameVerifier());
            //init(new PinSubjectTrustManager(), HttpsURLConnection.getDefaultHostnameVerifier());
            //init(new DirtyPinningTrustManager(), HttpsURLConnection.getDefaultHostnameVerifier());
            //init(new NoBasicConstraintsPinningTrustManager(), HttpsURLConnection.getDefaultHostnameVerifier());
            initGoodPinBadHostnameVerifier();
            //initBestPractice();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    SocketIoConnection(String uri, String username, String password,
                       final SimpleListener listener) {
        Log.d(TAG, "constructor");
        try {
            IO.Options options = new IO.Options();
            options.secure = true; // FIXME: strange option -- URI already defines whether it is secure or not
            options.forceNew = true;
            options.reconnection = false;
            options.timeout = 15000;
            options.query = "username=" + username + "&password=" + password;

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
                    if (args.length == 0) {
                        Log.e(TAG, "onConnectError: Unknown");
                    } else if (args[0] instanceof Exception) {
                        Exception ex = (Exception) args[0];
                        ex.printStackTrace();
                    } else {
                        Log.e(TAG, "onConnectError: " + args[0].toString());
                    }

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
                    listener.onMessage((String) args[0]);
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

