
rule TrojanDropper_AndroidOS_Rootnik_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Rootnik.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 76 5f 72 6f 6f 74 32 } //01 00 
		$a_00_1 = {72 6f 6f 74 69 6e 67 20 75 73 69 6e 67 20 70 61 63 6b 61 67 65 } //01 00 
		$a_00_2 = {69 73 20 72 6f 6f 74 65 64 } //01 00 
		$a_00_3 = {70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //01 00 
		$a_00_4 = {75 70 64 61 74 65 20 72 6f 6f 74 20 64 62 } //01 00 
		$a_00_5 = {70 75 73 68 2e 61 70 6b } //00 00 
		$a_00_6 = {5d 04 00 00 70 } //94 04 
	condition:
		any of ($a_*)
 
}