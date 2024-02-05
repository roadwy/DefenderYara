
rule Backdoor_WinNT_Tofsee_A_sys{
	meta:
		description = "Backdoor:WinNT/Tofsee.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0 8b 45 08 89 41 01 8b 45 0c 2b c1 83 e8 0a c6 01 b9 c6 41 05 e9 } //03 00 
		$a_01_1 = {89 41 06 58 0f 22 c0 66 9d 8b c1 5d c2 08 00 53 56 57 bf 2e 6b 64 44 57 68 80 00 00 00 33 } //06 00 
		$a_01_2 = {74 10 8a 10 88 14 01 40 3b 45 08 75 f5 eb 03 8b 5d f8 8b 4d fc 8b 46 04 89 4e 04 8b f1 eb 07 4f } //01 00 
		$a_01_3 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00 
		$a_00_4 = {4d 6f 76 65 46 69 6c 65 45 78 41 } //01 00 
		$a_00_5 = {4e 74 57 72 69 74 65 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}