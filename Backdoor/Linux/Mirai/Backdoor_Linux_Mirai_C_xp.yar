
rule Backdoor_Linux_Mirai_C_xp{
	meta:
		description = "Backdoor:Linux/Mirai.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 49 4c 4c 42 4f 54 } //01 00  KILLBOT
		$a_00_1 = {6d 69 6f 72 69 20 72 65 6d 61 73 74 65 72 65 64 20 69 6e 66 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //01 00  miori remastered infection successful
		$a_00_2 = {32 30 39 2e 31 34 31 2e 36 31 2e 31 33 35 } //00 00  209.141.61.135
	condition:
		any of ($a_*)
 
}