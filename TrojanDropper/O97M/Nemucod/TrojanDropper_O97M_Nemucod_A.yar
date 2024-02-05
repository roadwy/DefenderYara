
rule TrojanDropper_O97M_Nemucod_A{
	meta:
		description = "TrojanDropper:O97M/Nemucod.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 65 73 6a 2e 22 29 29 0d 0a 76 62 5f } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 76 62 5f 90 02 10 28 22 6c 6c 65 68 53 2e 74 70 69 72 63 53 57 22 29 29 90 00 } //01 00 
		$a_01_2 = {28 22 6e 75 52 22 29 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}