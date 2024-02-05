
rule Backdoor_Linux_Gafgyt_BV_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BV!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 45 fc 8b 45 fc 89 45 d4 83 7d d4 ff 74 0b 83 7d d4 00 } //01 00 
		$a_00_1 = {8b 04 85 e0 4a 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 e0 4a 51 00 } //01 00 
		$a_00_2 = {48 8b 55 d8 0f b6 02 3c 72 75 10 8b 45 f0 89 45 e4 8b 7d f4 } //00 00 
	condition:
		any of ($a_*)
 
}