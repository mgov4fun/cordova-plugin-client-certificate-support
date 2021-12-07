package de.jstd.cordova.plugin;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaActivity;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;


public class ClientCertificateAuthentication extends CordovaPlugin {
    public static final String SP_KEY_ALIAS = "SP_KEY_ALIAS";
    public static final String TAG = "client-cert-auth";
    private static boolean ENABLED = false;

    X509Certificate[] mCertificates;
    PrivateKey mPrivateKey;

    @Override
    public void pluginInitialize() {
        Log.v(TAG, "Plugin cordova-plugin-injectview loaded.");
    }

    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }


    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        if (ENABLED){
            if (mCertificates == null || mPrivateKey == null) {
                loadKeys(request);
            } else {
                proceedRequest(request);
            }
        }
        return true;
    }

    private void loadKeys(ICordovaClientCertRequest request) {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(cordova.getActivity());
        final KeyChainAliasCallback callback = new AliasCallback(cordova.getActivity(), request);
        final String alias = sp.getString(SP_KEY_ALIAS, null);

        if (alias == null) {
            KeyChain.choosePrivateKeyAlias(cordova.getActivity(), callback,
                    new String[]{KeyProperties.KEY_ALGORITHM_RSA}, null, request.getHost(), request.getPort(),
                    null);
        } else {
            ExecutorService threadPool = cordova.getThreadPool();
            threadPool.submit(() -> callback.alias(alias));
        }
    }

    public void proceedRequest(ICordovaClientCertRequest request) {
        request.proceed(mPrivateKey, mCertificates);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("registerAuthenticationCertificate")) {
            ENABLED = true;
            return true;
        }
        return false;
    }

    static class AliasCallback implements KeyChainAliasCallback {


        private final SharedPreferences mPreferences;
        private final ICordovaClientCertRequest mRequest;
        private final Context mContext;

        public AliasCallback(Context context, ICordovaClientCertRequest request) {
            mRequest = request;
            mContext = context;
            mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
        }

        @Override
        public void alias(String alias) {
            try {
                if (alias != null) {
                    SharedPreferences.Editor edt = mPreferences.edit();
                    edt.putString(SP_KEY_ALIAS, alias);
                    edt.apply();
                    PrivateKey pk = KeyChain.getPrivateKey(mContext, alias);
                    X509Certificate[] cert = KeyChain.getCertificateChain(mContext, alias);
                    mRequest.proceed(pk, cert);
                } else {
                    mRequest.proceed(null, null);
                }
            } catch (KeyChainException e) {
                String errorText = "Failed to load certificates";
                Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText, e);
            } catch (InterruptedException e) {
                String errorText = "InterruptedException while loading certificates";
                Toast.makeText(mContext, errorText, Toast.LENGTH_SHORT).show();
                Log.e(TAG, errorText, e);
            }
        }
    }
}
