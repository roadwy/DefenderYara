
rule TrojanDropper_AndroidOS_Banker_Z_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 08 35 28 ?? ?? d8 04 04 52 48 07 03 08 14 09 50 2e 97 00 91 01 09 01 dc 09 08 03 48 09 06 09 da 0b 04 50 91 0b 01 0b da 04 04 00 b3 b4 b0 04 b0 74 93 07 01 01 b1 a7 b0 74 94 07 01 01 b0 74 b7 94 8d 44 4f 04 05 08 13 04 24 00 b3 b4 b0 14 d8 07 04 a8 d8 08 08 01 01 14 01 b1 28 d3 13 00 0a 00 13 02 11 00 35 20 ?? ?? 93 02 01 07 d8 00 00 01 28 f8 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}