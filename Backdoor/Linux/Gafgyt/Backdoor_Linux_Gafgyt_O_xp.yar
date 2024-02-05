
rule Backdoor_Linux_Gafgyt_O_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.O!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 61 64 64 79 6c 33 33 74 } //01 00 
		$a_00_1 = {59 6f 75 20 43 61 6e 20 46 69 6e 64 20 4d 65 20 41 74 20 79 61 6d 69 2e 63 72 69 6d 73 6f 6e 2e 72 69 70 20 2d 7b 64 61 64 64 79 6c 33 33 74 7d } //01 00 
		$a_00_2 = {4c 49 4b 55 47 69 6c 6b 75 74 37 36 39 34 35 38 39 30 35 } //01 00 
		$a_00_3 = {73 65 6e 64 43 4e 43 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}