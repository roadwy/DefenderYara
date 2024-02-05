
rule Backdoor_Linux_Mirai_CL_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {99 88 13 0d 1e 00 00 00 00 8c 9b 01 00 8c 9b 01 00 94 } //01 00 
		$a_00_1 = {de f4 90 f7 20 ed 0a 87 ff 5b 46 3f 98 } //01 00 
		$a_00_2 = {4b df db 9b 4a eb cc 76 8f } //00 00 
	condition:
		any of ($a_*)
 
}