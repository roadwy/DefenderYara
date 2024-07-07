
rule TrojanDropper_AndroidOS_Banker_M_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 35 12 2f 00 d0 95 ee 42 48 09 03 02 14 0a 7e 11 05 00 b1 a4 dc 0a 02 02 48 0a 08 0a 14 0b cf 35 1d 00 92 0b 0b 04 b1 5b 93 0c 0b 0b d8 0c 0c ff b0 9c 92 09 05 04 da 09 09 00 b0 9c b3 44 dc 04 04 01 b0 4c 97 04 0c 0a 8d 44 4f 04 06 02 12 44 92 09 0b 05 b0 49 d8 02 02 01 01 b4 28 d2 13 00 1d 00 35 07 0a 00 da 00 09 59 b3 45 91 05 00 05 d8 07 07 01 28 f5 22 00 90 01 02 70 20 90 01 02 60 00 11 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}