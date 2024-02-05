
rule Trojan_Win32_Trickbot_A_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //01 00 
		$a_00_1 = {6b 00 6c 00 59 00 4b 00 41 00 6e 00 4d 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_02_2 = {8b c1 33 d2 f7 f7 41 8a 82 90 01 03 00 30 44 31 ff 81 f9 90 01 02 00 00 75 e7 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_A_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 90 01 01 8b 55 08 52 e8 90 01 04 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb 90 00 } //01 00 
		$a_02_1 = {57 8b ec 8b c7 05 90 01 04 68 f0 ff 00 00 89 45 04 59 8b d7 8b f7 8b c1 66 ad 85 c0 74 90 00 } //01 00 
		$a_00_2 = {51 8b c6 8b 00 46 8b 0f 33 c8 8b c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_A_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 65 c6 85 90 01 04 6c c6 85 90 01 04 65 c6 85 90 01 04 74 c6 85 90 01 04 65 c6 85 90 01 04 20 c6 85 90 01 04 57 c6 85 90 01 04 69 c6 85 90 01 04 6e c6 85 90 01 04 44 c6 85 90 01 04 65 c6 85 90 01 04 66 c6 85 90 01 04 65 c6 85 90 01 04 6e c6 85 90 01 04 64 90 00 } //01 00 
		$a_02_1 = {ff 20 c6 85 90 01 04 53 c6 85 90 01 04 65 c6 85 90 01 04 74 c6 85 90 01 04 2d c6 85 90 01 04 4d c6 85 90 01 04 70 c6 85 90 01 04 50 c6 85 90 01 04 72 c6 85 90 01 04 65 c6 85 90 01 04 66 c6 85 90 01 04 65 c6 85 90 01 04 72 c6 85 90 01 04 65 c6 85 90 01 04 6e c6 85 90 01 04 63 c6 85 90 01 04 65 c6 85 90 01 04 20 c6 85 90 01 04 2d c6 85 90 01 04 44 c6 85 90 01 04 69 c6 85 90 01 04 73 c6 85 90 01 04 61 c6 85 90 01 04 62 c6 85 90 01 04 6c c6 85 90 01 04 65 c6 85 90 01 04 52 c6 85 90 01 04 65 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}