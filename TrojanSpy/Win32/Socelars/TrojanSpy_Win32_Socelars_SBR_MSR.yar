
rule TrojanSpy_Win32_Socelars_SBR_MSR{
	meta:
		description = "TrojanSpy:Win32/Socelars.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 64 73 66 77 33 34 65 72 66 39 33 2e 63 6f 6d } //1 wdsfw34erf93.com
		$a_01_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //1 Google\Chrome\User Data
		$a_01_2 = {53 45 4c 45 43 54 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 20 77 68 65 72 65 20 6f 72 69 67 69 6e 5f 75 72 6c 20 4c 49 4b 45 } //1 SELECT username_value, password_value FROM logins where origin_url LIKE
		$a_01_3 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 76 61 6c 75 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 } //1 SELECT host_key, name, value, encrypted_value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}