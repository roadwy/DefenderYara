
rule Backdoor_Linux_Mirai_GV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 10 12 00 21 10 50 00 02 00 43 2a 39 90 01 03 00 00 40 ac 54 00 a3 8f 01 00 02 24 3d 90 01 03 02 00 02 24 12 90 01 03 01 00 11 24 98 80 99 8f 00 00 05 8e 4c 00 a4 8f 09 f8 20 03 90 00 } //01 00 
		$a_03_1 = {0f 00 84 30 80 18 03 00 2b 10 02 00 c0 20 04 00 25 18 64 00 40 10 02 00 2b 28 05 00 25 28 a3 00 25 10 c2 00 25 10 45 00 02 00 02 a1 18 00 e2 8c 00 00 00 00 02 90 01 03 80 ff 03 24 21 18 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}