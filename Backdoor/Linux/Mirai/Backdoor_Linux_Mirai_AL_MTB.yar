
rule Backdoor_Linux_Mirai_AL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 d0 03 01 89 eb 30 18 89 d0 03 01 89 fb 30 18 89 d0 03 01 89 f3 30 18 89 d0 03 01 8a 1c 24 30 18 42 8b 41 04 25 ff ff 00 00 39 d0 } //00 00 
	condition:
		any of ($a_*)
 
}