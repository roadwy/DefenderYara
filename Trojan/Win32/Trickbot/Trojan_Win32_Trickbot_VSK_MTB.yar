
rule Trojan_Win32_Trickbot_VSK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.VSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {8a 19 8b 45 ec 89 c1 81 c1 01 00 00 00 89 4d ec 88 18 8b 45 d4 8b 4d ac 01 c8 89 45 d4 eb } //02 00 
		$a_00_1 = {8b c1 33 d2 bd 3f 00 00 00 f7 f5 8a 04 1a 8a 14 31 32 d0 88 14 31 41 3b cf 75 } //02 00 
		$a_00_2 = {66 8b 75 d6 66 81 f6 25 79 66 89 75 d6 80 f2 4b 88 55 cb 8b 45 d0 05 ff ff ff ff 89 45 d0 eb } //02 00 
		$a_02_3 = {8b 4d d0 03 4d d8 0f be 19 e8 90 01 04 33 d8 8b 55 d0 03 55 d8 88 1a eb 90 00 } //02 00 
		$a_02_4 = {8b 4c 24 70 8b 54 24 18 89 35 90 01 04 89 35 90 01 04 8b f7 c1 ee 05 03 74 24 64 03 d9 03 d7 33 da 81 3d 90 01 04 72 07 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_VSK_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.VSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 48 5a 4c 43 76 79 58 74 44 73 4c 76 68 36 43 30 38 46 57 47 55 6e 71 4a 56 66 34 77 } //02 00 
		$a_01_1 = {69 67 52 4b 70 56 71 4a 66 42 65 6f 48 31 67 4d 41 76 53 72 44 55 44 35 6e 6f 37 66 45 73 } //02 00 
		$a_01_2 = {68 48 64 59 77 41 75 4b 6e 78 6f 6b 35 42 35 6e 72 43 70 59 52 30 4b 69 65 61 } //02 00 
		$a_01_3 = {68 31 6f 54 6f 6e 35 44 75 42 37 76 65 78 46 74 46 31 72 63 54 38 37 31 } //02 00 
		$a_01_4 = {69 34 4a 56 52 45 72 4f 35 46 63 74 4d 56 65 4c 36 6b 66 32 61 67 43 42 59 36 4a 42 68 75 } //00 00 
	condition:
		any of ($a_*)
 
}