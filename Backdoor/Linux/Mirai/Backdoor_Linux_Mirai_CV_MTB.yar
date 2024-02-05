
rule Backdoor_Linux_Mirai_CV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 74 6b 69 6c 6c } //01 00 
		$a_00_1 = {8b 44 24 28 c7 44 24 04 02 00 00 00 89 44 24 08 8b 44 24 20 89 04 24 e8 72 8f 00 00 eb c6 } //00 00 
	condition:
		any of ($a_*)
 
}