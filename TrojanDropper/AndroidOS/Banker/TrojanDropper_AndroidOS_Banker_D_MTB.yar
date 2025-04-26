
rule TrojanDropper_AndroidOS_Banker_D_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 35 12 2a 00 14 04 aa e8 0d 00 b1 48 48 04 03 02 14 05 f2 2d 06 00 b0 85 dc 09 02 ?? 48 09 07 09 91 0a 05 08 d8 0a 0a 3d b3 55 d8 05 05 ff b0 45 91 04 0a 08 da 04 04 00 b0 45 b3 88 dc 08 08 01 b0 85 97 04 05 09 8d 44 4f 04 06 02 d8 02 02 01 01 a8 28 d7 13 01 1d 00 35 10 05 00 d8 00 00 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}