
rule Backdoor_Linux_Mirai_EN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_00_0 = {7f 69 fe 70 7f c3 f3 78 7d 20 da 78 7c 00 48 50 7c 00 fe 70 7f bd 00 38 4b ff fc 31 3b e3 00 01 7f 9f e8 40 40 9d 00 0c 7f bf eb 78 3b 80 00 22 } //00 00 
	condition:
		any of ($a_*)
 
}