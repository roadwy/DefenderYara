
rule Ransom_Win64_FileCoder_KK_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d ?? ?? ?? ?? 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 f5 38 1b 00 43 33 1c 84 eb } //20
		$a_01_1 = {48 81 ec 98 00 00 00 48 89 ac 24 90 00 00 00 48 8d ac 24 90 00 00 00 48 89 84 24 a0 00 00 00 49 c7 c5 00 00 00 00 4c 89 ac 24 88 00 00 00 c6 44 24 3f 00 48 89 d9 48 8d 3d cf da 02 00 be 0b 00 00 00 48 89 c3 31 c0 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}