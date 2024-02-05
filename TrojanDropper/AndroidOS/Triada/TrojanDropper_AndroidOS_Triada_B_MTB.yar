
rule TrojanDropper_AndroidOS_Triada_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Triada.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 61 69 6e 2f 77 32 63 36 63 37 2f 6d 35 69 36 61 6e 39 2f } //01 00 
		$a_03_1 = {73 73 6b 30 31 35 2d 79 6d 32 90 09 0a 00 90 0f 04 00 2d 90 10 02 00 2d 90 10 02 00 90 00 } //01 00 
		$a_00_2 = {72 32 65 32 61 64 32 44 32 61 32 74 61 } //01 00 
		$a_00_3 = {4c 63 6f 6d 2f 7a 63 6f 75 70 2f 62 61 73 65 2f 63 6f 72 65 2f 5a 63 6f 75 70 53 44 4b 3b } //00 00 
		$a_00_4 = {5d 04 00 } //00 0b 
	condition:
		any of ($a_*)
 
}