
rule TrojanDropper_AndroidOS_SAgent_F_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 74 66 72 65 65 74 } //01 00  qtfreet
		$a_01_1 = {73 74 72 69 6e 67 65 72 73 61 6b 61 6c 61 6d } //01 00  stringersakalam
		$a_03_2 = {48 04 00 01 62 05 90 01 02 94 06 01 03 6e 20 90 01 02 65 00 0a 05 b7 54 8d 44 4f 04 00 01 d8 01 01 01 28 c9 90 00 } //01 00 
		$a_03_3 = {34 21 27 00 22 01 90 01 02 70 20 90 01 02 01 00 11 01 62 03 90 01 02 6e 20 90 01 02 07 00 0a 04 6e 20 90 01 02 43 00 0a 03 e0 03 03 04 62 04 90 01 02 d8 05 00 01 6e 20 90 01 02 57 00 0a 05 6e 20 90 01 02 54 00 0a 04 b6 43 6e 20 90 01 02 32 00 d8 00 00 02 28 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}