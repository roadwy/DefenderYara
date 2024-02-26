
rule Backdoor_Linux_Mirai_EH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 83 fa 20 48 89 d1 49 89 fa fc 76 53 48 89 f8 48 f7 d8 48 83 e0 07 48 29 c1 48 91 f3 a4 48 89 c1 48 83 e9 20 78 35 66 66 90 66 66 90 66 66 90 48 83 e9 20 48 8b 06 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 48 89 07 48 89 57 08 4c 89 47 10 4c 89 4f 18 48 8d 76 20 48 8d 7f 20 79 d4 48 83 c1 20 f3 a4 4c 89 d0 c3 90 90 45 31 c0 48 85 ff 41 ba 01 00 00 00 75 61 eb 76 48 0f be 07 4c 8b 0d b5 18 10 00 41 f6 04 41 08 74 64 31 d2 eb 15 6b d2 0a 0f be c1 8d 54 02 d0 81 fa ff 00 00 00 7f 4e 48 ff c7 } //01 00 
		$a_00_1 = {53 b8 64 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 76 0f e8 6c d5 ff ff 89 da 48 83 cb ff f7 da 89 10 48 89 d8 5b c3 } //01 00 
		$a_00_2 = {48 8d 3c 28 48 89 c3 e8 b9 02 00 00 85 c0 79 04 48 83 cb ff 5a 48 89 d8 5b 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}