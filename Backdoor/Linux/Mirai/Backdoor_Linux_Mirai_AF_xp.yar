
rule Backdoor_Linux_Mirai_AF_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 52 56 49 43 45 20 6e 6f 6f 70 } //01 00  SERVICE noop
		$a_01_1 = {47 45 54 46 55 43 4b 49 4e 47 } //01 00  GETFUCKING
		$a_01_2 = {4d 4f 4e 4b 45 59 30 3a } //01 00  MONKEY0:
		$a_01_3 = {77 65 6c 6c 2d 6b 6e 6f 77 6e 4c 6f 72 65 } //00 00  well-knownLore
	condition:
		any of ($a_*)
 
}