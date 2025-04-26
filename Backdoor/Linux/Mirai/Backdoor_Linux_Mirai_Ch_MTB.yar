
rule Backdoor_Linux_Mirai_Ch_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5 } //1
		$a_01_1 = {53 45 52 56 5a 55 58 4f } //1 SERVZUXO
		$a_01_2 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //1 killallbots
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Backdoor_Linux_Mirai_Ch_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 a0 e3 98 38 8d e5 04 30 83 e2 00 20 a0 e3 ?? 20 83 e7 04 30 83 e2 80 00 53 e3 fa ff ff 1a 18 28 8d e5 7c 30 43 e2 00 50 a0 e3 ?? 50 83 e7 04 30 83 e2 80 00 53 e3 ?? ff ff ?? a6 32 a0 e1 03 91 a0 } //1
		$a_03_1 = {30 d6 e5 b0 30 c3 e3 ?? 30 83 e3 00 30 c6 e5 00 10 d6 e5 01 30 a0 e3 09 30 c6 e5 0a 10 c1 e3 ?? 30 83 e2 05 10 81 } //1
		$a_00_2 = {eb ff 10 00 e2 20 34 a0 e1 20 28 a0 e1 00 00 51 e3 ?? 00 51 13 ff c0 03 e2 ff 20 02 e2 20 ec a0 e1 f5 ff ff 0a 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule Backdoor_Linux_Mirai_Ch_MTB_3{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {1c 55 9f e5 b4 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 1d ff ff 1a 00 34 95 e5 04 00 53 e3 1a ff ff 1a 02 0b 85 e2 08 00 80 e2 ?? ?? 00 eb 00 40 a0 e1 03 0b 85 e2 0c 00 80 e2 ?? ?? 00 eb 00 20 a0 e1 01 0b 85 e2 04 00 80 e2 04 10 a0 e1 ?? ?? 00 eb 0d ff ff ea } //1
		$a_03_1 = {04 e0 2d e5 24 c0 9f e5 00 30 a0 e1 0c d0 4d e2 00 10 93 e5 04 20 80 e2 00 c0 8d e5 10 00 9f e5 00 c0 a0 e3 0c 30 9f e5 04 c0 8d e5 ?? ?? 00 eb } //1
		$a_03_2 = {ec 57 9f e5 40 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 02 00 00 1a 00 34 95 e5 04 00 53 e3 fc 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}