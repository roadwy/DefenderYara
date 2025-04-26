
rule VirTool_Win64_Rovnix_C{
	meta:
		description = "VirTool:Win64/Rovnix.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 3c 11 13 13 13 13 75 09 } //1
		$a_03_1 = {81 f9 03 00 00 80 75 3d 4c 8d 0d ?? ?? ?? ?? 49 8b 09 48 85 c9 74 2e } //1
		$a_01_2 = {80 3b e8 75 0b b9 b9 05 00 00 66 39 4b 05 74 08 48 03 d8 44 39 2b eb da 8b 43 01 48 8d 5c 18 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}