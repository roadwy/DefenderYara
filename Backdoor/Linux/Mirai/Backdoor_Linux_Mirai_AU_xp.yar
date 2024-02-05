
rule Backdoor_Linux_Mirai_AU_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AU!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 20 2f 90 00 } //01 00 
		$a_01_1 = {54 56 57 53 56 50 56 54 } //01 00 
		$a_01_2 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f } //01 00 
		$a_01_3 = {2f 64 65 76 2f 6e 75 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}