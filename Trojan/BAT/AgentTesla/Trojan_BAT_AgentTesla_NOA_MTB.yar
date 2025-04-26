
rule Trojan_BAT_AgentTesla_NOA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 43 00 00 06 20 ?? ?? ?? 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b8 } //1
		$a_80_1 = {42 23 75 6e 23 69 66 75 23 5f 54 65 78 23 74 42 6f 23 78 } //B#un#ifu#_Tex#tBo#x  1
		$a_01_2 = {3d 72 df 02 10 03 e1 02 e0 02 eb 02 e6 02 e6 02 15 03 0d 03 f2 02 e1 02 f2 02 06 03 d4 02 cd 02 14 03 cd 02 cd 02 e3 02 ef 02 02 03 cf 02 df 02 ef 02 3d 72 e5 02 17 03 0d 03 3d 72 e0 02 eb 02 15 03 e1 02 3d 72 d1 02 df 02 05 03 3d 72 df 02 15 03 3d 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}