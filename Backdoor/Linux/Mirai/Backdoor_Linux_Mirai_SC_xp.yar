
rule Backdoor_Linux_Mirai_SC_xp{
	meta:
		description = "Backdoor:Linux/Mirai.SC!xp,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 69 6f 72 69 20 72 65 6d 61 73 74 65 72 65 64 20 69 6e 66 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //02 00 
		$a_01_1 = {4b 49 4c 4c 42 4f 54 } //02 00 
		$a_01_2 = {69 66 20 75 20 77 61 6e 6e 61 20 73 65 65 20 73 6f 75 72 63 65 20 68 65 72 65 3a 20 68 74 74 70 73 3a 2f 2f 72 6f 6f 74 5f 73 65 6e 70 61 69 2e 73 65 6c 6c 79 2e 73 74 6f 72 65 2f } //02 00 
		$a_01_3 = {36 53 52 53 3e 42 } //00 00 
	condition:
		any of ($a_*)
 
}