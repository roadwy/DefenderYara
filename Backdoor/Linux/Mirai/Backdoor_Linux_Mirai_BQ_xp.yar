
rule Backdoor_Linux_Mirai_BQ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 4f 43 52 59 53 59 52 43 } //01 00 
		$a_01_1 = {6e 70 78 78 6f 75 64 69 66 66 65 65 67 67 61 61 63 73 63 73 } //01 00 
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00 
		$a_01_3 = {6b 6b 76 65 74 74 67 61 61 61 73 65 63 6e 6e 61 61 61 61 } //01 00 
		$a_01_4 = {31 30 37 2e 31 37 34 2e 32 34 31 2e 32 30 39 } //01 00 
		$a_01_5 = {68 6b 6a 6d 6c 6f 6e 61 } //00 00 
	condition:
		any of ($a_*)
 
}