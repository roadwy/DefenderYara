
rule Backdoor_Linux_Mirai_AB_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 67 61 6d 65 6f 66 66 73 65 74 2e 78 79 7a } //01 00 
		$a_00_1 = {72 6d 20 2d 72 66 20 77 77 77 77 20 61 64 62 2e 73 68 } //01 00 
		$a_00_2 = {63 68 6d 6f 64 20 37 37 37 20 66 64 70 } //00 00 
	condition:
		any of ($a_*)
 
}