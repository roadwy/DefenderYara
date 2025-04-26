
rule TrojanSpy_BAT_AveMaria_MTB{
	meta:
		description = "TrojanSpy:BAT/AveMaria!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {0c 04 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 91 fe ?? ?? 00 61 d2 9c 00 fe ?? ?? 00 20 ?? ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 8e 69 fe ?? fe ?? ?? 00 fe ?? ?? 00 3a ?? ?? ff ff } //6
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_2 = {6c 6f 63 61 6c 46 69 6c 65 50 61 74 68 } //1 localFilePath
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_4 = {45 78 74 72 61 63 74 52 65 73 6f 75 72 63 65 54 6f 52 6f 6f 74 50 61 74 68 } //1 ExtractResourceToRootPath
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}