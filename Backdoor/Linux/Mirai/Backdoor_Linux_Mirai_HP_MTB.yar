
rule Backdoor_Linux_Mirai_HP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {f6 83 84 00 00 00 04 0f 44 c2 89 84 24 a0 00 00 00 31 d2 85 f6 74 04 8d 54 24 0c 31 c0 85 db 74 07 8d 84 24 98 00 00 00 6a 08 52 50 ff b4 24 3c 01 00 00 e8 99 00 00 00 83 c4 10 85 f6 89 c3 } //1
		$a_00_1 = {8b 73 08 75 17 69 06 6d 4e c6 41 05 39 30 00 00 25 ff ff ff 7f 89 06 89 45 00 eb 2b 8b 4b 04 8b 13 8b 7b 18 8b 01 01 02 8b 02 83 c2 04 d1 e8 39 fa 89 45 00 8d 41 04 72 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}