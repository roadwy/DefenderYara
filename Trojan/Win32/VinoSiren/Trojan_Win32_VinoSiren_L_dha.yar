
rule Trojan_Win32_VinoSiren_L_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.L!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00  SELECT origin_url, username_value, password_value FROM logins
		$a_01_1 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //01 00  SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins
		$a_01_2 = {2f 46 69 6c 65 5a 69 6c 6c 61 33 2f 52 65 63 65 6e 74 53 65 72 76 65 72 73 2f 53 65 72 76 65 72 2f 2a } //01 00  /FileZilla3/RecentServers/Server/*
		$a_01_3 = {2f 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2f 72 6f 6f 74 2f 63 6f 6e 74 61 69 6e 65 72 2f 63 6f 6e 6e 65 63 74 69 6f 6e 2f 63 6f 6e 6e 65 63 74 69 6f 6e 5f 69 6e 66 6f 2f 2a } //01 00  /configuration/root/container/connection/connection_info/*
		$a_01_4 = {7b 61 6c 6c 2c 62 72 6f 77 73 65 72 73 2c 6d 61 69 6c 73 2c 6f 74 68 65 72 73 7d } //00 00  {all,browsers,mails,others}
	condition:
		any of ($a_*)
 
}