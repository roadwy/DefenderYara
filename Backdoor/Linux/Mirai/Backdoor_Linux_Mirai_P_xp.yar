
rule Backdoor_Linux_Mirai_P_xp{
	meta:
		description = "Backdoor:Linux/Mirai.P!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 45 54 20 2f 90 02 10 90 03 06 04 61 72 6d 90 02 01 2f 73 70 63 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 90 00 } //01 00 
		$a_00_1 = {10 31 9f e5 88 30 8d e5 02 30 a0 e3 08 11 9f e5 08 21 9f e5 b4 38 cd e1 04 01 9f e5 05 3a a0 e3 b6 38 cd e1 b2 ff ff eb 01 10 a0 e3 00 70 a0 e1 06 20 a0 e1 02 00 a0 e3 da ff ff eb 01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 98 ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 af ff ff eb 00 00 50 e3 00 00 60 b2 91 ff ff bb 19 40 84 e2 05 00 a0 e1 ac 10 9f e5 04 20 a0 e1 b3 ff ff eb 04 00 50 e1 03 00 a0 13 89 ff ff 1b 98 80 9f e5 } //01 00 
		$a_02_2 = {47 45 54 20 2f 61 72 6d 90 01 01 2e 62 6f 74 2e 6c 65 20 48 54 54 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}