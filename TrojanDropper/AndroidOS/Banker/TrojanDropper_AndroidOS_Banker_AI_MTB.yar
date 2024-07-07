
rule TrojanDropper_AndroidOS_Banker_AI_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 20 2c 00 14 09 3b a7 00 00 b0 94 48 09 03 00 d9 0a 04 1f dc 0b 00 03 48 0b 08 0b da 0c 0a 4e 91 0c 04 0c b1 a4 b0 c4 da 04 04 00 b0 94 93 09 0c 0c b3 69 b7 69 b0 94 94 09 0c 0c b0 94 b7 b4 8d 44 4f 04 05 00 14 04 59 8a 7b 00 93 04 0c 04 d8 00 00 01 01 c4 28 d5 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}