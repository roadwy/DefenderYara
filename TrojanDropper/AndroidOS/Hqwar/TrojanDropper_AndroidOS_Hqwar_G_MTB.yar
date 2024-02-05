
rule TrojanDropper_AndroidOS_Hqwar_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 08 00 35 40 05 00 d8 00 00 01 28 fa 12 00 90 01 02 35 90 01 02 00 14 90 01 01 3b a7 00 00 b0 90 01 01 d9 90 01 01 01 1f da 90 01 02 4e 91 90 01 01 01 90 01 01 b1 90 01 01 b0 90 01 01 da 01 01 00 48 90 01 01 03 90 01 01 b0 90 01 01 93 90 00 } //01 00 
		$a_03_1 = {8d 11 4f 01 06 90 01 01 14 01 59 8a 7b 00 93 01 90 01 01 01 d8 90 01 02 01 01 90 01 01 28 90 01 01 13 00 13 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}