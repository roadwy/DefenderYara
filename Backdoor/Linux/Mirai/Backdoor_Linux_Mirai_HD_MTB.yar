
rule Backdoor_Linux_Mirai_HD_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 10 a0 e1 80 20 a0 e3 05 00 a0 e1 9b ff ff eb 00 20 50 e2 04 10 a0 e1 07 00 a0 e1 01 ?? ?? ?? 8b ff ff eb f5 ?? ?? ?? 05 00 a0 e1 69 ff ff eb 07 00 a0 e1 67 ff ff eb 3c 10 9f e5 04 20 a0 e3 01 00 a0 e3 82 ff ff eb 05 00 a0 e3 59 ff ff eb 98 d0 8d e2 f0 41 bd e8 } //1
		$a_03_1 = {20 21 9f e5 20 01 9f e5 aa ff ff eb 01 10 a0 e3 00 70 a0 e1 06 20 a0 e1 02 00 a0 e3 d2 ff ff eb 01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 ?? ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 a7 ff ff eb 00 40 50 e2 05 ?? ?? ?? 01 00 a0 e3 d8 10 9f e5 04 20 a0 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}