package ist.meic.sirs.securechildlocator;

import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.support.design.widget.FloatingActionButton;
import android.support.v4.widget.NestedScrollView;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.ArrayList;
import ist.meic.sirs.securechildlocator.exceptions.*;

public class BeaconManagerActivity extends AppCompatActivity {

    private Button addButton;
    private ListView listView;
    public EditText idText;
    public EditText passText;

    private ArrayList<String> listItems=new ArrayList<String>();
    private ArrayAdapter adapter;

    private Client c = null;
    private AddBeaconTask mAddTask = null;
    private ShowListTask mListTask = null;

    public BeaconManagerActivity() {
        this.c = Client.getInstance();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_beacon_manager);

        listView = (ListView) findViewById(R.id.list);
        idText = (EditText) findViewById(R.id.idText);
        passText = (EditText) findViewById(R.id.passText);

        addButton = (Button) findViewById(R.id.addButton);
        addButton.setOnClickListener( new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                attemptAddBeacon(view);
                attemptGetList();
            }
        });

        adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, listItems);
        listView.setAdapter(adapter);

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                String item = (String) parent.getItemAtPosition(position);
                Log.d("MANAGER", "Selected: " + item);
                Intent intent = new Intent(view.getContext(), BeaconTrackingActivity.class);
                //Only passing beaconID, maybe should pass password as well...
                intent.putExtra("beaconID", item);
                startActivity(intent);
            }
        });

        attemptGetList();
    }

    @Override
    public void onResume() {
        super.onResume();  // Always call the superclass method first
        //getListTask();
    }

    private boolean isIDValid(String id) {
        //TODO: Replace this with your own logic
        return id.length() > 4;
    }

    private boolean isPasswordValid(String password) {
        //TODO: Replace this with your own logic
        return password.length() > 4;
    }

    private void attemptAddBeacon(View view) {
        if (mAddTask!= null) {
            return;
        }
        // Reset errors.
        idText.setError(null);
        passText.setError(null);

        // Store values at the time of the login attempt.
        String id = idText.getText().toString();
        String password = passText.getText().toString();

        boolean cancel = false;
        View focusView = null;

        // Check for a valid password, if the user entered one.
        if (!TextUtils.isEmpty(password) && !isPasswordValid(password)) {
            passText.setError(getString(R.string.error_invalid_password));
            focusView = passText;
            cancel = true;
        }

        // Check for a valid email address.
        if (TextUtils.isEmpty(id)) {
            idText.setError(getString(R.string.error_field_required));
            focusView = idText;
            cancel = true;
        } else if (!isIDValid(id)) {
            idText.setError("This beacon ID is not valid!");
            focusView = idText;
            cancel = true;
        }

        if (cancel) {
            focusView.requestFocus();
        } else {

            mAddTask = new AddBeaconTask(id, password);
            mAddTask.execute((Void) null);
            try {
                if(mAddTask.get()) {
                    Log.d("MANAGER", "Beacon added with success");
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
    }

    private ArrayList<String> attemptGetList() {
        ArrayList<String> r_list = new ArrayList<String>();

        if (mListTask!= null) {
            return r_list;
        }

        boolean cancel = false;

        if (!cancel) {

            mListTask = new ShowListTask();
            mListTask.execute((Void) null);
            try {
                ArrayList<String> aux = mListTask.get();
                if(!aux.isEmpty()) {
                    Log.d("MANAGER", "List return from server successfully");

                    adapter.clear();

                    for(String id : aux) {
                        adapter.add(id);
                    }
                    adapter.notifyDataSetChanged();
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        return r_list;
    }

    public class AddBeaconTask extends AsyncTask<Void, Void, Boolean> {

        private final String id;
        private final String pass;

        private String ERROR_FLAG;

        AddBeaconTask(String beaconID, String beaconPass) {
            id = beaconID;
            pass = beaconPass;
        }

        @Override
        protected Boolean doInBackground(Void... params) {

            try {
                c.addBeacon(id, pass);
            } catch (ConnectionFailedException e) {
                Log.d("LOGIN", "Connection Failed");
                ERROR_FLAG = "CONNECTION";
                return false;
            } catch(IncorrectPasswordException e) {
                Log.d("LOGIN", "Wrong Password");
                ERROR_FLAG = "PASS";
                return false;
            } catch(BeaconDoesntExistException e) {
                Log.d("LOGIN", "Beacon Doesn't Exist");
                ERROR_FLAG = "NO BEACON";
                return false;
            } catch(BeaconAlreadyAddedException e) {
                Log.d("LOGIN", "Beacon already added");
                ERROR_FLAG = "BEACON ADDED";
                return false;
            }
            return true;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            mAddTask = null;

            if (success) {
                //finish();
            } else {
                switch(ERROR_FLAG) {
                    case "CONNECTION" :
                        idText.setError("Access Denied, possible connection problem");
                        idText.requestFocus();
                        passText.requestFocus();
                        break;
                    case "PASS":
                        passText.setError(getString(R.string.error_incorrect_password));
                        passText.requestFocus();
                        break;
                    case "NO BEACON":
                        idText.setError("This account doesn't exist.");
                        idText.requestFocus();
                        break;
                    case "BEACON ADDED":
                        //Toast.makeText(getApplicationContext(), "Beacon Added", Toast.LENGTH_LONG);
                        break;
                }
            }
        }

        @Override
        protected void onCancelled() {
            mAddTask = null;
        }
    }

    public class ShowListTask extends AsyncTask<Void, Void, ArrayList<String>> {

        ShowListTask() {}

        @Override
        protected ArrayList<String> doInBackground(Void... params) {
            ArrayList<String> r_list = new ArrayList<String>();

            try {
                r_list = c.getList();
            } catch (ConnectionFailedException e) {
                Log.d("MANAGER", "Connection Failed");
            } catch(ListDoesntContainElementsException e) {
                Log.d("MANAGER", "List doesn't exist");
            }
            return r_list;
        }

        @Override
        protected void onPostExecute(final ArrayList<String> list) {
            mListTask = null;

            if (!list.isEmpty()) {
                //finish();
            } else {
                Log.d("MANAGER", "ShowListTask Failed");
            }
        }

        @Override
        protected void onCancelled() {
            mListTask = null;
        }
    }
}
