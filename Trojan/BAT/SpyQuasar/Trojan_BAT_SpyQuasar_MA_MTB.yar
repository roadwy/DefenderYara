
rule Trojan_BAT_SpyQuasar_MA_MTB{
	meta:
		description = "Trojan:BAT/SpyQuasar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {06 17 6f 2b ?? ?? 0a 06 17 6f 2c ?? ?? 0a 90 0a 4f 00 73 24 00 00 0a 0a 06 72 ?? 06 00 70 72 ?? 07 00 70 7e 25 00 00 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 8c 24 00 00 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a } //1
		$a_81_1 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_81_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_5 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}