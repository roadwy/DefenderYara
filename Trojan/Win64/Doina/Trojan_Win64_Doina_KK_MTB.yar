
rule Trojan_Win64_Doina_KK_MTB{
	meta:
		description = "Trojan:Win64/Doina.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 4c 05 30 b8 4f ec c4 4e f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 1a 2b ca 80 c1 61 42 88 4c 05 38 4c 03 c6 49 83 f8 05 } //20
		$a_01_1 = {41 8a 04 0e 40 32 c5 88 01 48 ff c1 48 ff ca } //10
		$a_01_2 = {8a 04 16 41 32 c6 88 02 48 ff c2 49 ff c8 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}