
rule Backdoor_Linux_Mirai_HE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f0 41 2d e9 74 31 9f e5 98 d0 4d e2 00 80 a0 e3 00 00 00 ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 e2 fa 90 01 03 54 11 9f e5 90 00 } //1
		$a_03_1 = {01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 90 01 01 ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 a7 ff ff eb 00 40 50 e2 05 90 01 03 01 00 a0 e3 d8 10 9f e5 04 20 a0 e3 ad ff ff eb 00 00 64 e2 84 ff ff eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}