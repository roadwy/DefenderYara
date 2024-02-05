
rule Backdoor_Linux_Mirai_BL_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {7f c0 fe 70 83 81 00 10 7c 03 f2 78 83 a1 00 14 7c 63 00 50 80 01 00 24 7c 63 fe 70 83 c1 00 18 7f 63 18 38 83 e1 00 1c 83 61 00 0c 7c 08 03 a6 38 21 00 20 } //01 00 
		$a_00_1 = {2f 84 00 03 55 00 58 28 54 eb 6c fe 7d 00 02 78 7c eb 5a 78 2f 04 00 01 7c 0b 5a 78 54 00 c2 3e 7c 0a 03 78 7c 00 5a 78 41 bd ff b4 7d 40 5a 78 38 84 ff fe 41 9a 00 34 b0 03 00 00 38 63 00 02 } //00 00 
	condition:
		any of ($a_*)
 
}