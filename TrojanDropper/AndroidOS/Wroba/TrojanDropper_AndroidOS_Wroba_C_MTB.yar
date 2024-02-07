
rule TrojanDropper_AndroidOS_Wroba_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6d 79 63 6f 64 65 2e 64 65 78 00 65 78 69 73 74 73 00 64 65 6c 65 74 65 } //01 00 
		$a_00_1 = {00 61 6d 00 00 73 74 61 72 74 73 65 72 76 69 63 65 00 00 00 00 2d 6e 00 } //01 00 
		$a_01_2 = {2e 4c 6f 61 64 65 64 41 70 6b 00 6d 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00 
		$a_01_3 = {67 65 74 41 73 73 65 74 73 } //00 00  getAssets
	condition:
		any of ($a_*)
 
}