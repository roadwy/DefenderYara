
rule Backdoor_Linux_Mirai_DL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0d 0a 0a 0d 00 00 00 00 4b 6f 6d 6f 72 65 62 69 0d 0a } //01 00 
		$a_01_1 = {31 39 33 2e 34 32 2e 33 32 2e 31 37 35 00 00 00 2f } //00 00 
	condition:
		any of ($a_*)
 
}