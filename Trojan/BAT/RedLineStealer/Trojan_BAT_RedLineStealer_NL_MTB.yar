
rule Trojan_BAT_RedLineStealer_NL_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 1f 55 61 d1 2a 3a 03 0f 02 28 29 00 00 0a 28 2a 00 00 0a 2a } //5
		$a_80_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //GetProcAddress  1
		$a_80_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}
rule Trojan_BAT_RedLineStealer_NL_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 8f 3f 90 01 03 25 4b 03 06 95 61 54 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 90 00 } //5
		$a_03_1 = {00 02 06 8f 2d 90 01 03 25 47 03 06 91 61 d2 52 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_BAT_RedLineStealer_NL_MTB_3{
	meta:
		description = "Trojan:BAT/RedLineStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6b 6f 69 00 4b 6f 61 73 6f 66 6b 2e 65 78 65 } //1
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_2 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
		$a_01_3 = {00 52 65 73 6f 6c 76 65 45 76 65 6e 74 41 72 67 73 00 53 79 73 74 65 6d 00 44 65 63 6f 6d 70 72 65 73 73 00 } //1 刀獥汯敶癅湥䅴杲s祓瑳浥䐀捥浯牰獥s
		$a_01_4 = {00 4d 61 69 6e 00 52 65 73 6f 6c 76 65 00 } //1 䴀楡n敒潳癬e
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_7 = {52 65 73 6f 6c 76 65 4d 65 74 68 6f 64 } //1 ResolveMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}