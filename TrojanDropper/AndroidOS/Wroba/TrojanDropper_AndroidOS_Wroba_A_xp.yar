
rule TrojanDropper_AndroidOS_Wroba_A_xp{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {7b 44 20 1c 7a 44 04 93 b0 47 23 68 02 1c 29 1c 88 } //01 00 
		$a_00_1 = {44 7b 44 b0 47 22 68 49 49 03 90 a7 20 80 00 13 58 79 44 20 1c 98 47 23 68 00 } //01 00 
		$a_00_2 = {47 23 68 3e 4a 01 1c 08 33 db 6f 20 1c 7a } //00 00 
	condition:
		any of ($a_*)
 
}