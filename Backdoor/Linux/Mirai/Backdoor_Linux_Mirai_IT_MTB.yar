
rule Backdoor_Linux_Mirai_IT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 bf 8e 66 51 56 00 c7 a4 9b 66 58 33 0b fb c2 a9 9c 3c 44 3f 0a f1 df a8 ef 00 db a4 84 77 4d 3f 0b f1 85 bd 86 60 55 22 1d 90 00 df a8 83 7c 51 22 16 f9 cc aa 8a 60 1a 26 11 e2 ca b9 8a 12 00 df bf 86 71 5f 25 19 e2 ce f9 81 7b 53 31 1d } //1
		$a_01_1 = {e2 d8 e3 9f 7b 46 37 0c f5 ab 00 dd ac 82 62 5b 21 16 e3 85 a9 96 7c 34 00 d9 ac 96 70 5b 34 17 f9 d8 a5 db 6a 1a 32 01 fe ab 00 c8 a5 86 7c 51 25 1d f1 d9 a8 c1 7b 5a 32 01 90 00 cd a2 9d 76 47 24 1f f1 d2 e3 86 7c 50 2f 78 00 c7 a4 8c 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}