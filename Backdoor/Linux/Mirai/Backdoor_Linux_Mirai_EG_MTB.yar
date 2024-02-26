
rule Backdoor_Linux_Mirai_EG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 61 70 65 42 6f 74 2f 4b 69 6c 6c 65 72 2f } //01 00  VapeBot/Killer/
		$a_00_1 = {00 5b 56 61 70 65 42 6f 74 2f 4b 69 6c 6c 65 72 2f 45 58 45 5d 20 4b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 3a 20 25 73 2c 20 50 49 44 3a 20 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}