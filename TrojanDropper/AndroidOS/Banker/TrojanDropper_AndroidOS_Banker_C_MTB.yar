
rule TrojanDropper_AndroidOS_Banker_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_00_0 = {35 01 2e 00 14 06 3b a7 00 00 b0 64 48 06 02 01 d9 08 04 1f dc 09 01 03 48 09 07 09 da 0a 08 4e 91 0a 04 0a b1 84 b0 a4 da 04 04 00 b0 64 93 06 0a 0a db 06 06 01 df 06 06 01 b0 64 94 06 0a 0a b0 64 b7 94 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a4 28 d3 } //00 00 
	condition:
		any of ($a_*)
 
}