
rule Backdoor_Linux_Mirai_U_xp{
	meta:
		description = "Backdoor:Linux/Mirai.U!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 61 6c 6c 62 6f 74 73 } //01 00 
		$a_01_1 = {62 6f 74 6e 65 74 66 6f 72 6b } //01 00 
		$a_01_2 = {75 64 70 70 70 6c 61 69 6e 61 74 74 61 63 6b } //01 00 
		$a_01_3 = {61 63 6b 61 74 74 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}