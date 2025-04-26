
rule Trojan_BAT_Coinminer_GA_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 "
		
	strings :
		$a_80_0 = {77 61 74 63 68 64 6f 67 } //watchdog  10
		$a_80_1 = {5c 72 6f 6f 74 5c 63 69 6d 76 32 } //\root\cimv2  5
		$a_80_2 = {53 65 6c 65 63 74 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 77 68 65 72 65 20 4e 61 6d 65 3d 27 7b 30 7d 27 } //Select CommandLine from Win32_Process where Name='{0}'  5
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_4 = {43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //CreateNoWindow  1
		$a_80_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_6 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //CreateEncryptor  1
		$a_80_7 = {47 65 74 54 65 6d 70 50 61 74 68 } //GetTempPath  1
		$a_80_8 = {43 6f 6d 62 69 6e 65 } //Combine  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=25
 
}