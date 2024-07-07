
rule Trojan_Win32_Stealer_H_bit{
	meta:
		description = "Trojan:Win32/Stealer.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b c3 89 45 90 01 01 ff 75 90 01 01 8d 34 1f ff 15 90 01 04 8b c8 33 d2 8b c7 f7 f1 8b 45 90 01 01 8b 4d 90 01 01 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8 90 00 } //1
		$a_01_1 = {53 45 4c 45 43 54 20 61 63 74 69 6f 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT action_url, username_value, password_value FROM logins
		$a_01_2 = {53 45 4c 45 43 54 20 62 61 73 65 44 6f 6d 61 69 6e 2c 20 6e 61 6d 65 2c 20 76 61 6c 75 65 20 46 52 4f 4d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //1 SELECT baseDomain, name, value FROM moz_cookies
		$a_01_3 = {53 45 4c 45 43 54 20 48 4f 53 54 5f 4b 45 59 2c 6e 61 6d 65 2c 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 20 66 72 6f 6d 20 63 6f 6f 6b 69 65 73 } //1 SELECT HOST_KEY,name,encrypted_value from cookies
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}