
rule TrojanDropper_AndroidOS_Banker_H_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 00 35 20 2d 00 14 08 12 2f 06 00 b1 58 48 05 04 00 14 09 61 c5 0b 00 b0 93 dc 09 00 03 48 09 07 09 14 0a 9f 55 02 00 b1 3a b1 8a 93 0b 0a 0a d8 0b 0b ff b0 5b 91 05 03 08 da 05 05 00 b0 5b b3 88 dc 08 08 01 b0 8b 97 05 0b 09 8d 55 4f 05 06 00 d8 00 00 01 01 35 01 a3 28 d4 13 00 1a 00 35 01 0a 00 14 00 c7 07 0b 00 93 00 03 00 d8 01 01 01 28 f5 22 00 90 01 02 70 20 90 01 02 60 00 11 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}