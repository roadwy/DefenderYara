
rule TrojanDropper_O97M_GraceWire_AF_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 22 64 6c 90 02 09 6c 22 90 00 } //01 00 
		$a_03_1 = {3d 20 55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 20 26 20 22 5c 90 02 20 22 20 2b 20 22 2e 78 6c 90 00 } //01 00 
		$a_03_2 = {2b 20 22 2e 22 20 2b 20 22 7a 90 02 09 70 22 90 00 } //01 00 
		$a_01_3 = {22 5c 6f 6c 65 4f 62 6a 65 63 74 22 } //01 00  "\oleObject"
		$a_01_4 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f } //00 00  ExecuteExcel4Macro
	condition:
		any of ($a_*)
 
}