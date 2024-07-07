
rule TrojanDropper_AndroidOS_Banker_L_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 10 21 00 14 06 dc ac 0e 00 b1 68 48 06 02 00 d0 55 77 f5 dc 09 00 02 48 09 07 09 14 0a 03 ac 02 00 91 08 05 08 b0 a8 b7 96 8d 66 4f 06 04 00 13 06 1f 29 b3 56 d8 00 00 01 01 8b 01 58 01 b5 28 e0 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}