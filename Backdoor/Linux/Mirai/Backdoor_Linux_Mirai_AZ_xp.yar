
rule Backdoor_Linux_Mirai_AZ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AZ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {18 00 80 90 21 00 e0 a8 21 30 b1 00 ff 30 d3 00 ff 93 b4 00 4b 03 20 f8 09 24 10 } //01 00 
		$a_00_1 = {00 24 8f 99 80 cc 8f bf 00 54 8f be 00 50 8f b7 00 } //00 00 
	condition:
		any of ($a_*)
 
}