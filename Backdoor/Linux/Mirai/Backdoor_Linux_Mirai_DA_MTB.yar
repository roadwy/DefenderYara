
rule Backdoor_Linux_Mirai_DA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {b0 30 d7 e1 40 00 13 e3 1e 00 00 0a 38 40 87 e2 04 20 a0 e1 08 10 9d e5 05 00 a0 e1 0b c0 99 e7 0f e0 a0 e1 1c ff 2f e1 04 00 a0 e1 08 c0 99 e7 0f e0 a0 e1 1c ff 2f e1 b0 30 d7 e1 0c 20 9d e5 03 30 82 e1 05 3d 23 e2 0d 0d 13 e3 08 00 00 1a 07 00 a0 e1 } //1
		$a_00_1 = {ac 30 9f e5 18 40 80 e2 04 20 a0 e1 03 10 96 e7 0d 00 a0 e1 9c 30 9f e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 00 80 e0 e3 04 00 a0 e1 88 30 9f e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 00 40 97 e5 01 10 a0 e3 74 30 9f e5 0d 00 a0 e1 00 80 87 e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 0c 00 97 e5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}