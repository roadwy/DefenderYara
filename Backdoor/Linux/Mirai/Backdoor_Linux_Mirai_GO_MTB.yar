
rule Backdoor_Linux_Mirai_GO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 1a ff 3c fd 75 90 01 01 c6 44 1a ff fc eb 90 01 01 3c fb 75 90 01 01 c6 44 1a ff fd 42 83 fa 04 90 00 } //01 00 
		$a_03_1 = {66 3b 50 08 72 90 01 01 66 3b 50 0a 72 90 01 01 41 83 c0 10 39 d9 7c 90 01 01 31 c0 89 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}