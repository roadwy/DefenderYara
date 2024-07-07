
rule TrojanDropper_AndroidOS_Bian_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Bian.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {12 03 35 23 2d 00 48 05 00 03 14 09 90 12 05 00 b0 69 dc 0a 03 01 48 0a 07 0a d3 6b e5 7d b0 9b da 0c 0b 00 b3 9c b0 1c b0 5c 93 05 06 06 d8 05 05 ff b0 5c b4 66 b0 6c 97 05 0c 0a 8d 55 4f 05 04 03 14 05 0a d1 00 00 14 06 2c 9f 09 00 b3 95 b1 5b b0 b6 d8 03 03 01 01 95 28 d4 13 00 1c 00 35 08 07 00 93 00 05 06 d8 08 08 01 28 f8 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}