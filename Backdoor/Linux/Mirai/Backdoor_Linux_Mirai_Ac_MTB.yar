
rule Backdoor_Linux_Mirai_Ac_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Ac!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 65 72 5d 20 73 63 61 6e 6e 69 6e 67 20 25 73 } //1 killer] scanning %s
		$a_00_1 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //1 Multihop attempted
		$a_00_2 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //1
		$a_00_3 = {68 2b 64 05 08 e8 f6 30 00 00 e8 ee 2d 00 00 66 c7 05 14 b3 05 08 02 00 a3 08 b3 05 08 c7 05 18 b3 05 08 41 de ca 35 66 c7 05 16 b3 05 08 00 50 e8 58 1f 00 00 c7 05 70 90 05 08 d0 eb 04 08 e8 59 fd ff ff e8 b4 06 00 00 58 5a 6a 20 8d ac 24 ac 05 00 00 55 e8 c3 2b 00 00 83 c4 10 83 fe 02 0f 84 98 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}