
rule Backdoor_Linux_Hutizu_A_xp{
	meta:
		description = "Backdoor:Linux/Hutizu.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 44 50 41 54 54 41 43 4b } //1 UDPATTACK
		$a_00_1 = {8d b6 00 00 00 00 8d 42 01 a3 24 0c 0f 08 ff 14 85 1c e0 0e 08 8b 15 24 0c 0f 08 39 da 72 e7 } //1
		$a_00_2 = {b8 b0 81 05 08 85 c0 74 0c c7 04 24 54 29 0e 08 e8 d2 ff 00 00 c6 05 20 0c 0f 08 01 } //1
		$a_00_3 = {00 c7 44 24 04 5c 98 0c 08 89 04 24 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}