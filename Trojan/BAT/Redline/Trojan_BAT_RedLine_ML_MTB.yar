
rule Trojan_BAT_RedLine_ML_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 04 8e 69 8d ?? ?? ?? 01 13 02 38 ?? ?? ?? ?? 11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c 20 ?? ?? ?? ?? 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff } //10
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {4c 6f 67 69 6e 55 74 69 6c 73 } //1 LoginUtils
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}