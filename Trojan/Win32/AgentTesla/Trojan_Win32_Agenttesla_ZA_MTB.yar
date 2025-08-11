
rule Trojan_Win32_Agenttesla_ZA_MTB{
	meta:
		description = "Trojan:Win32/Agenttesla.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 } //1 GetPrivateProfileString
		$a_01_1 = {67 65 74 5f 4f 53 46 75 6c 6c 4e 61 6d 65 } //1 get_OSFullName
		$a_01_2 = {72 65 6d 6f 76 65 5f 4b 65 79 } //1 remove_Key
		$a_01_3 = {46 74 70 57 65 62 52 65 71 75 65 73 74 } //1 FtpWebRequest
		$a_01_4 = {6c 6f 67 69 6e 73 } //1 logins
		$a_01_5 = {31 2e 38 35 20 28 48 61 73 68 2c 20 76 65 72 73 69 6f 6e 20 32 2c 20 6e 61 74 69 76 65 20 62 79 74 65 2d 6f 72 64 65 72 29 } //1 1.85 (Hash, version 2, native byte-order)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}