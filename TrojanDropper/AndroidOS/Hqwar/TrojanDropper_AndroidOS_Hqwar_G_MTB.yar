
rule TrojanDropper_AndroidOS_Hqwar_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 08 00 35 40 05 00 d8 00 00 01 28 fa 12 00 ?? ?? 35 ?? ?? 00 14 ?? 3b a7 00 00 b0 ?? d9 ?? 01 1f da ?? ?? 4e 91 ?? 01 ?? b1 ?? b0 ?? da 01 01 00 48 ?? 03 ?? b0 ?? 93 } //1
		$a_03_1 = {8d 11 4f 01 06 ?? 14 01 59 8a 7b 00 93 01 ?? 01 d8 ?? ?? 01 01 ?? 28 ?? 13 00 13 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}