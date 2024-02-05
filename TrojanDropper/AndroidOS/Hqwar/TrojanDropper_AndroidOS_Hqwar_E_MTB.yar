
rule TrojanDropper_AndroidOS_Hqwar_E_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d2 00 99 0b 90 02 04 b0 30 90 02 04 54 d3 c0 19 90 02 04 21 33 90 02 04 54 d4 c3 19 90 02 04 21 44 90 02 04 b1 43 90 02 04 b0 30 90 02 04 52 d3 c8 19 90 02 04 d0 33 5d 09 90 02 04 d0 33 12 05 90 02 04 d8 03 03 48 90 02 04 52 d4 bb 19 90 02 04 b0 43 90 02 04 b0 30 90 02 04 59 d0 bc 19 90 02 04 54 d0 bd 19 90 02 04 21 00 90 02 04 d1 00 0f 3f 90 00 } //01 00 
		$a_00_1 = {63 6f 6d 2f 6e 65 6f 68 62 69 2f 63 65 76 7a 73 69 77 } //00 00 
	condition:
		any of ($a_*)
 
}