
rule Backdoor_Linux_Mirai_HH_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c 40 1b e5 01 00 74 e3 03 01 00 0a 02 00 54 e3 02 30 e0 03 26 90 01 03 04 00 54 e3 00 30 a0 13 01 30 a0 03 90 00 } //01 00 
		$a_03_1 = {84 40 a0 e1 06 30 84 e2 03 30 c3 e3 0d d0 63 e0 38 c0 4b e2 04 c0 8d e5 07 00 a0 e1 3c c0 4b e2 02 10 a0 e3 60 20 4b e2 10 30 8d e2 08 c0 8d e5 00 40 8d e5 9a 03 00 eb 22 00 50 e3 03 90 01 03 3c 30 1b e5 01 00 73 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}