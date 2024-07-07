
rule Trojan_BAT_Heracles_CXCF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CXCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 55 6c 75 5a 47 56 34 49 41 3d 3d } //1 CUluZGV4IA==
		$a_01_1 = {4f 69 41 3d 38 52 57 78 6c 62 57 56 75 64 48 4d 67 62 32 59 67 51 6d 6c } //1 OiA=8RWxlbWVudHMgb2YgQml
		$a_01_2 = {30 51 58 4a 79 59 58 6b 67 49 47 46 6d 64 47 56 79 49 48 } //1 0QXJyYXkgIGFmdGVyIH
		$a_01_3 = {4e 6c 64 48 52 70 62 6d 63 67 5a 6d 46 73 63 32 55 36 } //1 NldHRpbmcgZmFsc2U6
		$a_01_4 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 SmartAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}