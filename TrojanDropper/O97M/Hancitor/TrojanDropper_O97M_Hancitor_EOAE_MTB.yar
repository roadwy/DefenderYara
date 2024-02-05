
rule TrojanDropper_O97M_Hancitor_EOAE_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 6f 6d 73 68 2e 64 6c 6c 22 } //01 00 
		$a_03_1 = {49 66 20 54 65 72 73 2e 4e 61 6d 65 20 3d 20 22 90 02 04 2e 64 6c 6c 22 20 54 68 65 6e 90 00 } //01 00 
		$a_01_2 = {46 6f 72 20 45 61 63 68 20 4e 65 64 63 20 49 6e 20 6d 64 73 2e 53 75 62 46 6f 6c 64 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}