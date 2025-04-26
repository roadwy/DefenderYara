
rule TrojanDropper_AndroidOS_Banker_Y_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 12 2a 00 14 04 01 2d 0c 00 b0 49 d1 94 16 07 da 05 09 4d b1 45 da 09 09 00 b3 59 b0 09 48 07 03 02 b0 79 93 07 04 04 d8 07 07 ff b0 79 94 07 04 04 b0 79 dc 07 02 02 48 07 08 07 b7 97 8d 77 4f 07 06 02 14 07 0f ad 83 00 b3 74 d8 02 02 01 01 59 28 d7 } //5
	condition:
		((#a_00_0  & 1)*5) >=5
 
}