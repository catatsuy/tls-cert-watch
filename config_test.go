package main

import (
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	targets, err := loadConfig(strings.NewReader(`[{"host":"example.test","key_types":["RSA","ECDSA"]},{"host":"::1","port":8443,"key_types":["ECDSA"]}]`))
	if err != nil || targets[0].Port != 443 || targets[1].Port != 8443 {
		t.Fatalf("%+v %v", targets, err)
	}
	for _, input := range []string{`[]`, `null`, `{}`, `[{"host":"https://example.test","key_types":["RSA"]}]`, `[{"host":"a","key_types":[]}]`, `[{"host":"a","port":-1,"key_types":["RSA"]}]`, `[{"host":"a","port":65536,"key_types":["RSA"]}]`, `[{"host":"a","key_types":["rsa"]}]`, `[{"host":"a","key_types":["RSA","RSA"]}]`, `[{"host":"a","key_types":["RSA"],"typo":true}]`, `[{"host":"a","key_types":["RSA"]}] []`, `[{"host":"-bad","key_types":["RSA"]}]`} {
		if _, err := loadConfig(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}
