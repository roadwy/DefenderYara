
rule TrojanDropper_AndroidOS_Banker_J_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 35 12 29 00 48 06 03 02 d8 08 04 f8 dc 09 02 02 48 09 07 09 91 0a 04 08 d8 0a 0a 3d b3 44 d8 04 04 ff b0 64 91 06 0a 08 da 06 06 00 b0 64 93 06 08 08 dc 06 06 01 b0 64 b7 94 8d 44 4f 04 05 02 13 04 29 00 b3 84 d8 04 04 46 b1 a4 d8 02 02 01 28 d8 13 01 2e 00 35 10 05 00 d8 00 00 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}