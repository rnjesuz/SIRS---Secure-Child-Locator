package ist.meic.sirs.securechildlocator;

import android.content.Context;
import android.content.Intent;
import android.support.design.widget.FloatingActionButton;
import android.support.v4.widget.NestedScrollView;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
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

import java.util.ArrayList;

public class BeaconManagerActivity extends AppCompatActivity {

    private LinearLayout popupWindow;
    private Button addButton;
    private ListView list;
    private EditText idText;
    private EditText passText;

    private ArrayList<String> listItems=new ArrayList<String>();
    private ArrayAdapter<String> adapter;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_beacon_manager);

        //TO TEST GPS
        listItems.add("Beacon Test");

        list = (ListView) findViewById(R.id.list);
        idText = (EditText) findViewById(R.id.idText);
        passText = (EditText) findViewById(R.id.passText);

        addButton = (Button) findViewById(R.id.addButton);
        addButton.setOnClickListener( new Button.OnClickListener() {
            @Override
            public void onClick(View view) {
                addBeaconToList(view);
            }
        });

        adapter = new ArrayAdapter<String>
                (this, android.R.layout.simple_list_item_1, listItems);
        list.setAdapter(adapter);

        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position,
                                    long id) {
                Intent intent = new Intent(getBaseContext(), BeaconTrackingActivity.class);
                startActivity(intent);
            }
        });
    }

    public void addBeaconToList(View view){
        EditText id = (EditText) findViewById(R.id.idText);
        EditText pass = (EditText) findViewById(R.id.passText);

        if(validate(id.getText().toString(), pass.getText().toString())) {
            listItems.add(id.getText().toString());
            adapter.notifyDataSetChanged();
        }
    }

    private boolean validate(String id, String pass) {
        View focusView = null;
        boolean cancel = false;

        idText.setError(null);
        passText.setError(null);

        if (!isPasswordValid(pass)) {
            idText.setError(getString(R.string.error_invalid_password));
            focusView = passText;
            cancel = true;
        }

        if(!isIDValid(id)) {
            idText.setError(getString(R.string.error_invalid_id));
            focusView = idText;
            cancel = true;
        }

        if(!cancel) {
            //Launch Async task to authenticate
            return true;
        } else return false;
    }

    private boolean isIDValid(String id) {
        //TODO: Replace this with your own logic
        return id.length() > 4;
    }

    private boolean isPasswordValid(String password) {
        //TODO: Replace this with your own logic
        return password.length() > 4;
    }
}
