
rule TrojanDropper_O97M_Hancitor_JOAB_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 78 6c 20 3d 20 22 5c 7a 6f 22 20 26 20 22 72 6f 2e 22 20 26 20 22 64 } //01 00 
		$a_01_1 = {6f 78 6c 20 3d 20 6f 78 6c 20 26 20 22 6f } //01 00 
		$a_01_2 = {6f 78 6c 20 3d 20 6f 78 6c 20 26 20 22 63 } //01 00 
		$a_01_3 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 6f 78 6c } //01 00 
		$a_01_4 = {43 61 6c 6c 20 75 6f 69 61 28 61 61 61 61 29 } //00 00 
	condition:
		any of ($a_*)
 
}