
rule Trojan_BAT_AgentTesla_NNO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 06 20 90 01 03 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d b8 90 00 } //1
		$a_01_1 = {f2 02 f4 02 0f 03 ef 02 3d 72 eb 02 3d 72 3d 72 e3 02 3d 72 3d 72 cd 02 cd 02 d6 02 3d 72 ea 02 05 03 3d 72 3d 72 3d 72 } //1
		$a_01_2 = {df 02 e5 02 d6 02 df 02 00 03 05 03 3d 72 df 02 e2 02 e3 02 df 02 ea 02 05 03 df 02 18 03 df 02 e1 02 d2 02 df 02 eb 02 } //1
		$a_80_3 = {41 6c 70 68 61 2e 42 65 74 61 } //Alpha.Beta  1
		$a_80_4 = {42 23 75 6e 23 69 66 75 23 5f 54 65 78 23 74 42 6f 23 78 } //B#un#ifu#_Tex#tBo#x  1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}