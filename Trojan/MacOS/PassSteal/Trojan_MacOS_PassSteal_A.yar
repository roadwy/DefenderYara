
rule Trojan_MacOS_PassSteal_A{
	meta:
		description = "Trojan:MacOS/PassSteal.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 5f 73 74 65 61 6c 65 72 73 2e 72 73 53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 3b } //1 data_stealers.rsSELECT origin_url, username_value, password_value FROM logins;
		$a_03_1 = {66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 66 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 70 72 6f 63 65 73 73 73 72 63 2f 62 72 6f 77 73 65 72 73 2f [0-10] 2f 6d 6f 64 75 6c 65 73 2f 6b 65 79 5f 73 74 65 61 6c } //1
		$a_00_2 = {2e 64 62 53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 2c 20 70 61 74 68 2c 20 65 78 70 69 72 65 73 5f 75 74 63 2c 20 69 73 5f 73 65 63 75 72 65 2c 20 69 73 5f 68 74 74 70 6f 6e 6c 79 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 3b } //1 .dbSELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies;
		$a_00_3 = {66 69 72 65 66 6f 78 2e 2e 6d 6f 64 75 6c 65 73 2e 2e 64 61 74 61 5f 73 74 65 61 6c 65 72 73 2e 2e 44 61 74 61 53 74 65 61 6c 65 72 24 47 54 24 31 33 67 65 74 5f 70 61 73 73 77 6f 72 64 73 } //1 firefox..modules..data_stealers..DataStealer$GT$13get_passwords
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}