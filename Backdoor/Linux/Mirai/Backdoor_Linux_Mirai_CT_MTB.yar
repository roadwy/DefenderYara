
rule Backdoor_Linux_Mirai_CT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {10 a0 e1 00 a0 a0 e1 16 20 a0 e3 04 00 a0 e1 b4 3d 9f e5 81 07 00 eb 05 10 a0 e1 00 80 a0 e1 18 20 a0 e3 04 00 a0 e1 01 30 a0 e3 73 08 00 eb 05 10 a0 e1 07 20 a0 e3 50 30 a0 e3 00 60 a0 } //1
		$a_00_1 = {e3 df 30 43 e2 0c 20 a0 e1 18 c0 4b e2 03 20 cc e7 51 3c e0 e3 e7 30 43 e2 01 20 a0 e1 18 e0 4b e2 03 20 ce e7 00 30 a0 e3 c4 30 0b } //1
		$a_00_2 = {04 e0 9d e4 1e ff 2f e1 ba 79 37 9e 3c 76 02 00 b9 79 37 9e 6c 00 9f e5 00 30 90 e5 01 30 83 e2 f0 41 2d e9 60 80 9f e5 03 ea a0 e1 2e ea a0 e1 0e 21 98 e7 49 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}