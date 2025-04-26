
rule Backdoor_Linux_Mirai_AE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 30 d1 e5 00 00 53 e3 01 30 ce e5 01 c0 8e e2 20 00 00 0a 01 30 d1 e5 00 00 53 e3 01 30 cc e5 01 10 81 e2 01 c0 8c e2 1a 00 00 0a 01 30 d1 e5 00 00 53 e3 01 30 cc e5 01 10 81 e2 01 e0 8c e2 14 00 00 0a 01 c0 d1 e5 01 30 81 e2 00 00 5c e3 01 c0 ce e5 01 10 83 e2 01 e0 8e e2 0d 00 00 0a 01 00 50 e2 e5 ff ff 1a 03 20 02 e2 } //2
		$a_03_1 = {6a 6e 64 69 3a 6c 64 ?? 70 3a 2f 2f [0-20] 2f } //1
		$a_00_2 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //2
		$a_00_3 = {0c 04 00 02 52 c2 44 02 0c 04 ff fb 53 c0 12 00 49 c1 44 81 0c 03 ff 83 57 c0 44 00 c0 02 02 80 00 00 00 ff c0 81 66 00 f1 76 0c 03 ff 84 57 c0 44 00 c4 00 42 80 10 02 c2 80 66 00 f1 62 0c 03 ff 86 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=3
 
}