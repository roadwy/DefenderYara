
rule Trojan_BAT_ClipBanker_MA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {09 69 8d 2c 00 00 01 25 17 28 ?? ?? ?? 06 13 04 06 28 ?? ?? ?? 06 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f ?? ?? ?? 2b 2a } //1
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {53 6c 65 65 70 } //1 Sleep
		$a_01_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_8 = {44 65 62 75 67 67 65 72 } //1 Debugger
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}