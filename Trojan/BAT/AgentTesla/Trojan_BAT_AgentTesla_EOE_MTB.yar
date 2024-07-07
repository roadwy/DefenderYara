
rule Trojan_BAT_AgentTesla_EOE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d 45 27 1d b6 81 85 c7 01 32 f1 d2 b6 2a 7e 64 4b 79 1b a6 39 65 6d a7 33 0f 2d b9 00 f9 84 11 c7 db f7 5d 8f be a2 e4 f9 ab e2 bd 4c b8 05 a7 } //1
		$a_01_1 = {22 b8 81 bd fd 80 21 75 ce 7a 8e a9 b7 d5 c4 f3 23 5a 71 ab f4 87 29 27 02 d8 7d a1 2f e8 86 b3 7e da 3f e1 bd 93 56 b5 e6 60 6b a7 3d 1f 0e 7f } //1
		$a_01_2 = {2f c6 de 32 36 51 3f d5 d2 4b 45 b2 d5 ab e2 bd 4c b8 f5 da 47 28 2f c6 de 32 36 51 3f d5 d2 4b 45 b2 d5 ab e2 bd 4c b8 f5 da 47 28 2f c6 de 32 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}