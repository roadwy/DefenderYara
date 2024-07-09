
rule TrojanDropper_AndroidOS_Banker_TA_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.TA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 09 12 7a 35 a9 0a 00 da 06 01 2c d9 06 06 11 b0 56 d8 09 09 01 28 f6 12 09 35 29 34 00 14 05 ?? ?? 1f 00 b0 56 48 05 04 09 d1 11 93 26 dc 0a 09 03 48 0a 08 0a ?? 0b 01 06 d8 0b 0b ec 93 0c 0b 0b d8 0c 0c ff b0 5c b1 16 da 06 06 00 b0 6c 93 05 01 01 dc 05 05 01 b0 5c 97 05 0c 0a 8d 55 4f 05 07 09 14 05 c6 b1 00 00 14 06 2d e1 0b 00 b0 b5 93 06 01 06 b1 65 d8 09 09 01 01 16 01 b1 ?? ?? 13 00 12 00 35 03 0c 00 13 00 16 00 91 02 01 05 b3 60 91 06 02 00 d8 03 03 01 ?? ?? 22 00 c6 14 70 20 ?? ?? 70 00 11 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}