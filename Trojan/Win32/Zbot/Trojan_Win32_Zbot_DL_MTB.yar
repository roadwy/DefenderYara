
rule Trojan_Win32_Zbot_DL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 0d 88 be 40 00 b8 67 66 66 66 8b d1 2b d7 f7 ea c1 fa 04 8b c2 c1 e8 1f 03 d0 89 54 24 40 0f 84 80 00 00 00 33 f6 3b fb 75 04 33 d2 eb 13 2b cf b8 67 66 66 66 f7 e9 c1 fa 04 8b ca c1 e9 1f 03 d1 3b f2 74 5f } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 66 69 6c 65 2e 75 74 69 6c 68 65 61 76 65 6e 2e 63 6f 2e 6b 72 2f 4e 45 54 2f 4e 45 54 30 30 31 2f 41 4c 54 6f 6f 6c 62 61 72 32 34 2e 65 78 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 66 69 6c 65 2d 67 75 72 69 2e 63 6f 2e 6b 72 2f 62 75 6e 2f 75 74 69 6c 5f 69 6e 64 65 78 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}