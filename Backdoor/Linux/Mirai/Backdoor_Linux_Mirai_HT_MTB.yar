
rule Backdoor_Linux_Mirai_HT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_00_0 = {89 d0 8a 5c 24 0f 03 01 30 18 89 d0 03 01 8a 5c 24 10 30 18 89 d0 03 01 8a 5c 24 20 30 18 89 d0 89 f3 42 03 01 30 18 } //00 00 
	condition:
		any of ($a_*)
 
}