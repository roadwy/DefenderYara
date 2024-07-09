
rule TrojanDropper_AndroidOS_Banker_AL_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 00 35 20 2f 00 14 01 3b a7 00 00 b0 15 48 01 03 00 d9 08 05 1f dc 09 00 03 48 09 07 09 da 0a 08 4e 91 0a 05 0a b1 85 b0 a5 da 05 05 00 b0 15 93 01 0a 0a db 01 01 01 df 01 01 01 b0 15 94 01 0a 0a b0 15 97 01 05 09 8d 11 4f 01 06 00 14 01 59 8a 7b 00 93 01 0a 01 d8 00 00 01 01 a5 ?? ?? 13 00 13 00 13 01 2f 00 35 10 05 00 d8 00 00 01 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}