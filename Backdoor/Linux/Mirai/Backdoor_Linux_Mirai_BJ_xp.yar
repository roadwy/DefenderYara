
rule Backdoor_Linux_Mirai_BJ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 04 85 20 e1 50 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 20 e1 50 00 } //01 00 
		$a_00_1 = {8b 0d 39 d9 10 00 8b 55 f0 8b 45 f4 89 c3 29 d3 89 da 89 c8 89 14 85 20 e1 50 00 89 c8 8b 04 85 20 e1 50 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Mirai_BJ_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.BJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 62 6f 74 20 70 72 6f 63 20 73 74 61 72 74 69 6e 67 2e 2e 2e } //01 00  hbot proc starting...
		$a_01_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00  /bin/busybox
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00  hlLjztqZ
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
	condition:
		any of ($a_*)
 
}