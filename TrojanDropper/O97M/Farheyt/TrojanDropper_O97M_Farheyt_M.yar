
rule TrojanDropper_O97M_Farheyt_M{
	meta:
		description = "TrojanDropper:O97M/Farheyt.M,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 63 53 22 29 20 2b 20 55 63 61 73 65 28 22 72 49 50 74 22 29 20 2b 20 55 63 61 73 65 28 22 49 4e 67 2e 22 29 } //01 00 
		$a_00_1 = {3d 20 22 46 69 22 20 26 20 55 63 61 73 65 28 22 6c 45 73 79 73 54 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 74 63 65 6a 62 4f 6d 65 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}