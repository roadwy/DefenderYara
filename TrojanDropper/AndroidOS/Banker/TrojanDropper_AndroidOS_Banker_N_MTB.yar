
rule TrojanDropper_AndroidOS_Banker_N_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 35 02 1e 00 d8 08 08 5f 48 06 01 02 d8 05 05 dd dc 09 02 03 48 09 07 09 14 0a 0b a5 38 00 b1 58 b1 a8 b7 96 8d 66 4f 06 04 02 13 06 36 47 b3 86 d8 02 02 01 01 8b 01 58 01 b5 28 e3 13 00 21 00 35 03 05 00 d8 03 03 01 28 fa 22 00 90 01 02 70 20 90 01 02 40 00 11 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}