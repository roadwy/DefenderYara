
rule Backdoor_Linux_Gafgyt_X_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.X!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {77 67 65 74 20 2d 73 20 2d 55 } //01 00 
		$a_01_1 = {4b 50 44 49 50 44 4c 50 44 4c 50 44 41 50 44 54 50 44 54 50 44 4b } //01 00 
		$a_01_2 = {4c 50 44 4f 50 44 4c 50 44 4e 50 44 4f 50 44 47 50 44 54 50 44 46 50 44 4f } //01 00 
		$a_01_3 = {48 50 44 4f 50 44 4c 50 44 44 20 4a 50 44 55 50 44 4e 50 44 4b } //01 00 
		$a_01_4 = {55 50 44 44 50 44 50 } //00 00 
		$a_00_5 = {5d 04 00 } //00 db 
	condition:
		any of ($a_*)
 
}