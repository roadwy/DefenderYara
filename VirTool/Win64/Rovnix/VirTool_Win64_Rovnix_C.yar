
rule VirTool_Win64_Rovnix_C{
	meta:
		description = "VirTool:Win64/Rovnix.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 3c 11 13 13 13 13 75 09 } //01 00 
		$a_03_1 = {81 f9 03 00 00 80 75 3d 4c 8d 0d 90 01 04 49 8b 09 48 85 c9 74 2e 90 00 } //01 00 
		$a_01_2 = {80 3b e8 75 0b b9 b9 05 00 00 66 39 4b 05 74 08 48 03 d8 44 39 2b eb da 8b 43 01 48 8d 5c 18 05 } //00 00 
	condition:
		any of ($a_*)
 
}