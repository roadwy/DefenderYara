
rule Backdoor_Linux_Bew_A_xp{
	meta:
		description = "Backdoor:Linux/Bew.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 51 81 ec 14 0d 00 00 8b 41 04 } //01 00 
		$a_00_1 = {8a 54 5e 01 8d 42 d0 3c 09 76 16 8d 42 9f 3c 05 77 05 8d 42 a9 } //01 00 
		$a_00_2 = {8a 14 03 84 d2 75 f5 c6 04 01 00 5b 5d } //00 00 
	condition:
		any of ($a_*)
 
}