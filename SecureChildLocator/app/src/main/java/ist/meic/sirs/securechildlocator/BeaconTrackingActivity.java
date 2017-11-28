package ist.meic.sirs.securechildlocator;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.ActivityCompat;
import android.support.v4.app.FragmentActivity;
import android.util.Log;
import android.widget.Toast;

import com.google.android.gms.maps.CameraUpdateFactory;
import com.google.android.gms.maps.GoogleMap;
import com.google.android.gms.maps.OnMapReadyCallback;
import com.google.android.gms.maps.SupportMapFragment;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.MarkerOptions;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import ist.meic.sirs.securechildlocator.R;
import ist.meic.sirs.securechildlocator.exceptions.ConnectionFailedException;
import ist.meic.sirs.securechildlocator.exceptions.ListDoesntContainElementsException;

public class BeaconTrackingActivity extends FragmentActivity implements OnMapReadyCallback {

    private GoogleMap mMap;
    private LocationManager mLocationManager;
    private ReqCoordsTask mReqTask = null;

    private String beaconID;
    private Client c = null;

    public BeaconTrackingActivity() {
        c = Client.getInstance();
    }

    private final LocationListener mLocationListener = new LocationListener() {
        @Override
        public void onLocationChanged(final Location location) {
            /*LatLng pos = new LatLng(location.getLatitude(), location.getLongitude());

            Toast.makeText(BeaconTrackingActivity.this, "Location Changed", Toast.LENGTH_SHORT).show();

            mMap.addMarker(new MarkerOptions().position(pos).title("You Are Here!"));
            mMap.moveCamera(CameraUpdateFactory.newLatLng(pos));*/
        }

        @Override
        public void onStatusChanged(String s, int i, Bundle bundle) {

        }

        @Override
        public void onProviderEnabled(String s) {

        }

        @Override
        public void onProviderDisabled(String s) {

        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_beacon_tracking);

        Intent intent = getIntent();
        beaconID = intent.getStringExtra("beaconID");

        Handler handler=new Handler();
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                attemptGetCoords();
            }
        },5000);

        // Obtain the SupportMapFragment and get notified when the map is ready to be used.
        SupportMapFragment mapFragment = (SupportMapFragment) getSupportFragmentManager()
                .findFragmentById(R.id.map);
        mapFragment.getMapAsync(this);

        mLocationManager = (LocationManager) getSystemService(LOCATION_SERVICE);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED
                && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "NO PERMISSION TO GET LOCALIZATION", Toast.LENGTH_SHORT).show();
            ActivityCompat.requestPermissions(this, new String[] {
                            Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION },
                    2);
        }
        mLocationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 5000,
                10, mLocationListener);
    }


    /**
     * Manipulates the map once available.
     * This callback is triggered when the map is ready to be used.
     * This is where we can add markers or lines, add listeners or move the camera. In this case,
     * we just add a marker near Sydney, Australia.
     * If Google Play services is not installed on the device, the user will be prompted to install
     * it inside the SupportMapFragment. This method will only be triggered once the user has
     * installed Google Play services and returned to the app.
     */
    @Override
    public void onMapReady(GoogleMap googleMap) {
        mMap = googleMap;
    }

    private void attemptGetCoords() {

        if (mReqTask!= null) {

        }

        boolean cancel = false;

        if (!cancel) {

            mReqTask = new BeaconTrackingActivity.ReqCoordsTask();
            mReqTask.execute((Void) null);
            try {
                String rcv = mReqTask.get();
                if(!rcv.isEmpty()) {
                    Log.d("TRACK", "Coords returned from server " + rcv);
                    String[] coords = rcv.split("_");
                    LatLng pos = new LatLng(Double.parseDouble(coords[0]), Double.parseDouble(coords[1]));
                    mMap.addMarker(new MarkerOptions().position(pos).title(beaconID));
                    mMap.moveCamera(CameraUpdateFactory.newLatLng(pos));
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
    }

    public class ReqCoordsTask extends AsyncTask<Void, Void, String> {

        @Override
        protected String doInBackground(Void... params) {
           String coords = "";

            coords = c.getCoordinates(beaconID);
            /*try {
                //get coordinates
            } catch (ConnectionFailedException e) {
                Log.d("MANAGER", "Connection Failed");
            } catch(ListDoesntContainElementsException e) {
                Log.d("MANAGER", "List doesn't exist");
            }*/
            return coords;
        }

        @Override
        protected void onPostExecute(final String coords) {
            mReqTask = null;

           /* if (!list.isEmpty()) {
                //finish();
            } else {
                Log.d("MANAGER", "ShowListTask Failed");
            }*/
        }

        @Override
        protected void onCancelled() {
            mReqTask = null;
        }
    }
}
