/**
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.remoteprovisioner;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.content.Context;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.security.remoteprovisioning.AttestationPoolStatus;
import android.security.remoteprovisioning.ImplInfo;
import android.security.remoteprovisioning.IRemoteProvisioning;
import android.util.Log;

import java.time.Duration;

/**
 * A class that extends JobService in order to be scheduled to check the status of the attestation
 * key pool at regular intervals. If the job determines that more keys need to be generated and
 * signed, it drives that process.
 */
public class PeriodicProvisioner extends JobService {

    private static final int FAILURE_MAXIMUM = 5;

    // How long to wait in between key pair generations to avoid flooding keystore with requests.
    private static final Duration KEY_GENERATION_PAUSE = Duration.ofMillis(1000);

    private static final String SERVICE = "android.security.remoteprovisioning";
    private static final String TAG = "RemoteProvisioningService";
    private ProvisionerThread mProvisionerThread;

    /**
     * Starts the periodic provisioning job, which will occasionally check the attestation key pool
     * and provision it as necessary.
     */
    public boolean onStartJob(JobParameters params) {
        Log.d(TAG, "Starting provisioning job");
        mProvisionerThread = new ProvisionerThread(params, this);
        mProvisionerThread.start();
        return true;
    }

    /**
     * Allows the job to be stopped if need be.
     */
    public boolean onStopJob(JobParameters params) {
        mProvisionerThread.stop();
        return false;
    }

    private class ProvisionerThread extends Thread {
        private Context mContext;
        private JobParameters mParams;

        ProvisionerThread(JobParameters params, Context context) {
            mParams = params;
            mContext = context;
        }

        public void run() {
            try {
                if (SettingsManager.getExtraSignedKeysAvailable(mContext) == 0) {
                    // Provisioning is disabled. Check with the server if it's time to turn it back
                    // on. If not, quit.
                    GeekResponse check = ServerInterface.fetchGeek(mContext);
                    if (check.numExtraAttestationKeys == 0) {
                        jobFinished(mParams, false /* wantsReschedule */);
                        return;
                    }
                }
                IRemoteProvisioning binder =
                        IRemoteProvisioning.Stub.asInterface(ServiceManager.getService(SERVICE));
                if (binder == null) {
                    Log.e(TAG, "Binder returned null pointer to RemoteProvisioning service.");
                    jobFinished(mParams, true /* wantsReschedule */);
                    return;
                }
                ImplInfo[] implInfos = binder.getImplementationInfo();
                if (implInfos == null) {
                    Log.e(TAG, "No instances of IRemotelyProvisionedComponent registered in "
                               + SERVICE);
                    jobFinished(mParams, true /* wantsReschedule */);
                    return;
                }
                int[] keysNeededForSecLevel = new int[implInfos.length];
                boolean provisioningNeeded = false;
                for (int i = 0; i < implInfos.length; i++) {
                    keysNeededForSecLevel[i] =
                            generateNumKeysNeeded(binder,
                                       SettingsManager.getExpiringBy(mContext)
                                                      .plusMillis(System.currentTimeMillis())
                                                      .toMillis(),
                                       implInfos[i].secLevel);
                    if (keysNeededForSecLevel[i] > 0) {
                        provisioningNeeded = true;
                    }
                }
                if (provisioningNeeded) {
                    GeekResponse resp = ServerInterface.fetchGeek(mContext);
                    if (resp == null) {
                        if (SettingsManager.getFailureCounter(mContext) > FAILURE_MAXIMUM) {
                            SettingsManager.clearPreferences(mContext);
                        }
                        jobFinished(mParams, true /* wantsReschedule */);
                        return;
                    }
                    // Updates to configuration will take effect on the next check.
                    SettingsManager.setDeviceConfig(mContext,
                                                    resp.numExtraAttestationKeys,
                                                    resp.timeToRefresh,
                                                    resp.provisioningUrl);
                    if (resp.numExtraAttestationKeys == 0) {
                        // If the server has sent this, deactivate RKP.
                        binder.deleteAllKeys();
                        jobFinished(mParams, false /* wantsReschedule */);
                        return;
                    }
                    for (int i = 0; i < implInfos.length; i++) {
                        Provisioner.provisionCerts(keysNeededForSecLevel[i],
                                                   implInfos[i].secLevel,
                                                   resp.getGeekChain(implInfos[i].supportedCurve),
                                                   resp.getChallenge(),
                                                   binder,
                                                   mContext);
                    }
                }
                jobFinished(mParams, false /* wantsReschedule */);
            } catch (RemoteException e) {
                jobFinished(mParams, true /* wantsReschedule */);
                Log.e(TAG, "Error on the binder side during provisioning.", e);
            } catch (InterruptedException e) {
                jobFinished(mParams, true /* wantsReschedule */);
                Log.e(TAG, "Provisioner thread interrupted.", e);
            }
        }

        /**
         * This method will generate and bundle up keys for signing to make sure that there will be
         * enough keys available for use by the system when current keys expire.
         *
         * Enough keys is defined by checking how many keys are currently assigned to apps and
         * generating enough keys to cover any expiring certificates plus a bit of buffer room
         * defined by {@code sExtraSignedKeysAvailable}.
         *
         * This allows devices to dynamically resize their key pools as the user downloads and
         * removes apps that may also use attestation.
         */
        private int generateNumKeysNeeded(IRemoteProvisioning binder, long expiringBy, int secLevel)
                throws InterruptedException, RemoteException {
            AttestationPoolStatus pool = binder.getPoolStatus(expiringBy, secLevel);
            int unattestedKeys = pool.total - pool.attested;
            int validKeys = pool.attested - pool.expiring;
            int keysInUse = pool.attested - pool.unassigned;
            int totalSignedKeys = keysInUse + SettingsManager.getExtraSignedKeysAvailable(mContext);
            int generated;
            for (generated = 0;
                    generated + unattestedKeys + validKeys < totalSignedKeys; generated++) {
                binder.generateKeyPair(false /* isTestMode */, secLevel);
                // Prioritize provisioning if there are no keys available. No keys being available
                // indicates that this is the first time a device is being brought online.
                if (pool.total != 0) {
                    Thread.sleep(KEY_GENERATION_PAUSE.toMillis());
                }
            }
            if (totalSignedKeys - validKeys > 0) {
                return generated + unattestedKeys;
            }
            return 0;
        }
    }
}
