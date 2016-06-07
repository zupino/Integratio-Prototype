/*
       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements.  See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership.  The ASF licenses this file
       to you under the Apache License, Version 2.0 (the
       "License"); you may not use this file except in compliance
       with the License.  You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.
 */

package com.tcz.httpReq;

import android.os.Bundle;
import org.apache.cordova.*;
import net.hockeyapp.android.CrashManager;

public class MainActivity extends CordovaActivity
{
  @Override
  public void onCreate(Bundle savedInstanceState)
  {
      super.onCreate(savedInstanceState);
      // Set by <content src="index.html" /> in config.xml
      loadUrl(launchUrl);
      checkForUpdates();
  }

  @Override
  public void onResume() {
    super.onResume();
    // ... your own onResume implementation
    checkForCrashes();
  }

  @Override
  public void onPause() {
    super.onPause();
    unregisterManagers();
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    unregisterManagers();
  }

  private void checkForCrashes() {
    CrashManager.register(this);
  }

  private void checkForUpdates() {
    // Remove this for store builds!
    //UpdateManager.register(this);
  }

  private void unregisterManagers() {
    //UpdateManager.unregister();
  }
}
