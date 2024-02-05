
rule Backdoor_WinNT_Nuwar_B_sys{
	meta:
		description = "Backdoor:WinNT/Nuwar.B!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 3d 93 08 75 07 8b 45 0c 8b 00 eb 1a 66 3d 28 0a 75 08 8b 45 0c 8b 40 04 eb 0c 66 3d ce 0e 75 18 } //01 00 
		$a_00_1 = {50 8b 45 fc fa 0f 22 c0 fb 58 8b c1 } //01 00 
		$a_00_2 = {8b ec 51 50 0f 20 c0 89 45 fc 25 ff ff fe ff fa 0f 22 c0 fb 58 8b 45 fc } //01 00 
		$a_00_3 = {8b 45 0c 89 18 8b 7e 04 4f 78 31 8b c7 c1 e0 06 8d b4 } //01 00 
		$a_02_4 = {01 00 6a 40 8d 9b 90 01 02 01 00 8b 43 50 68 00 30 00 00 89 45 f4 8d 45 f4 50 6a 00 8d 45 fc 50 ff 75 08 ff 15 90 00 } //01 00 
		$a_02_5 = {13 01 00 30 90 90 90 01 02 01 00 40 3b c1 72 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}