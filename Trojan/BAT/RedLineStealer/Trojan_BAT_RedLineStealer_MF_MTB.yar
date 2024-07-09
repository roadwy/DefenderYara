
rule Trojan_BAT_RedLineStealer_MF_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f ?? ?? ?? 0a 0b 16 0c 2b 14 06 08 07 08 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 9c 08 17 58 0c 08 06 8e 69 32 e6 06 2a } //10
		$a_01_1 = {6b 65 79 5f 72 65 67 69 73 74 65 72 } //1 key_register
		$a_01_2 = {72 65 76 73 74 72 69 6e 67 } //1 revstring
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {70 72 6f 66 65 73 73 6f 72 } //1 professor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}
rule Trojan_BAT_RedLineStealer_MF_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {36 35 2e 32 31 2e 31 39 39 2e 31 34 } //1 65.21.199.14
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //1 StringDecrypt
		$a_81_3 = {43 72 65 61 74 65 53 68 61 64 6f 77 43 6f 70 79 } //1 CreateShadowCopy
		$a_81_4 = {67 65 74 5f 49 50 } //1 get_IP
		$a_81_5 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_6 = {67 65 74 5f 4e 61 6d 65 4f 66 42 72 6f 77 73 65 72 } //1 get_NameOfBrowser
		$a_81_7 = {67 65 74 5f 43 6f 6f 6b 69 65 73 } //1 get_Cookies
		$a_81_8 = {67 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //1 get_Credentials
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}