package com.jwz.encrypt.demo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;

import com.jwz.encrypt.EncryptionClient;
import com.jwz.encrypt.base.TextUtils;
import com.jwz.encrypt.oneway.MD5Util;

public class MainActivity extends AppCompatActivity {

    private EditText mEtContent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mEtContent = findViewById(R.id.et_content);

        mEtContent.setText(EncryptionClient.randomEncryptKey());

        findViewById(R.id.btn_encrypt).setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                String content = mEtContent.getText().toString();
                if (!TextUtils.isEmpty(content)) {
                    mEtContent.setText(MD5Util.md5WithSalt(content));
                }
            }
        });
    }
}
