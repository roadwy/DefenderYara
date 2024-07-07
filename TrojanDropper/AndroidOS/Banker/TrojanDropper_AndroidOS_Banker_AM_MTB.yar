
rule TrojanDropper_AndroidOS_Banker_AM_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AM!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 24 2e 00 14 05 3b a7 00 00 b0 51 48 05 03 04 d9 08 01 1f dc 09 04 03 48 09 07 09 da 0a 08 4e 91 0a 01 0a b1 81 b0 a1 da 01 01 00 b0 51 93 05 0a 0a db 05 05 01 df 05 05 01 b0 51 94 05 0a 0a b0 51 b7 91 8d 11 4f 01 06 04 14 01 59 8a 7b 00 93 01 0a 01 d8 04 04 01 01 a1 28 d3 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}