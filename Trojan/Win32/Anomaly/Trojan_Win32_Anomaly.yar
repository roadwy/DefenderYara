
rule Trojan_Win32_Anomaly{
	meta:
		description = "Trojan:Win32/Anomaly,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 46 52 5f 53 74 65 61 6c 65 72 5f 90 04 04 0a 30 31 32 33 34 35 36 37 38 39 } //1
		$a_01_1 = {2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //1 .purple\accounts.xml
		$a_01_2 = {5c 54 68 65 20 42 61 74 21 5c 00 25 73 25 73 5c 41 63 63 6f 75 6e 74 2e 63 66 6e } //1
		$a_01_3 = {53 45 4c 45 43 54 20 68 6f 73 74 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}