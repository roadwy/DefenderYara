
rule TrojanDropper_AndroidOS_Banker_AG_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 21 2e 00 14 06 3b a7 00 00 b0 64 48 06 03 01 d9 09 04 1f dc 0a 01 03 48 0a 08 0a da 0b 09 4e 91 0b 04 0b b1 94 b0 b4 da 04 04 00 b0 64 93 06 0b 0b db 06 06 01 df 06 06 01 b0 64 94 06 0b 0b b0 64 b7 a4 8d 44 4f 04 07 01 14 04 59 8a 7b 00 93 04 0b 04 d8 01 01 01 01 b4 28 d3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}