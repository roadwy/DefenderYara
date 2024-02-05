
rule TrojanDropper_O97M_Hancitor_EMLU_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMLU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 4d 73 4d 70 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00 
		$a_01_1 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00 
		$a_01_2 = {70 6c 6f 70 20 26 20 22 5c 4d 73 4d 70 2e 64 6c 6c 22 29 } //01 00 
		$a_01_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //00 00 
	condition:
		any of ($a_*)
 
}