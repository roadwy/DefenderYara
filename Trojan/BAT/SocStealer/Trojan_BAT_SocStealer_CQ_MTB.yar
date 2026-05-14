
rule Trojan_BAT_SocStealer_CQ_MTB{
	meta:
		description = "Trojan:BAT/SocStealer.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {61 70 70 5f 62 6f 75 6e 64 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 app_bound_encrypted_key
		$a_81_1 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 } //1 SELECT origin_url,username_value,password_value
		$a_81_2 = {46 52 4f 4d 20 6d 6f 7a 5f 70 6c 61 63 65 73 20 57 48 45 52 45 20 76 69 73 69 74 5f 63 6f 75 6e 74 3e 30 } //1 FROM moz_places WHERE visit_count>0
		$a_81_3 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //1 payload.exe
		$a_81_4 = {73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //1 screenshot.jpg
		$a_81_5 = {76 32 30 5f 64 65 63 72 79 70 74 } //1 v20_decrypt
		$a_81_6 = {73 79 73 74 65 6d 5f 69 6e 66 6f 2e 74 78 74 } //1 system_info.txt
		$a_81_7 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}