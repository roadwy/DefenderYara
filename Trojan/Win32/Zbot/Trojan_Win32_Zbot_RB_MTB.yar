
rule Trojan_Win32_Zbot_RB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d b2 6e 00 00 89 45 18 8b 4d f0 83 c1 08 2b 4d 14 89 4d ec c7 45 e4 c0 f1 0f 00 8b 55 ec 69 d2 7b 46 01 00 a1 90 01 04 2b c2 89 45 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 52 4a 5a 45 42 55 4d 4a 47 43 48 4e 4c 51 58 4f 50 4b 4b 51 57 44 4f 4b 44 } //01 00  YRJZEBUMJGCHNLQXOPKKQWDOKD
		$a_01_1 = {42 47 42 41 51 46 58 51 5a } //01 00  BGBAQFXQZ
		$a_01_2 = {53 4f 57 51 4b 46 54 } //00 00  SOWQKFT
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 65 00 6e 00 63 00 68 00 61 00 69 00 73 00 20 00 64 00 65 00 27 00 63 00 6f 00 72 00 20 00 74 00 65 00 27 00 6c 00 65 00 27 00 67 00 75 00 69 00 64 00 65 00 72 00 6f 00 6e 00 74 00 } //01 00  Clenchais de'cor te'le'guideront
		$a_01_1 = {70 00 75 00 63 00 65 00 61 00 75 00 78 00 20 00 62 00 72 00 61 00 6e 00 63 00 61 00 72 00 64 00 69 00 65 00 72 00 73 00 } //01 00  puceaux brancardiers
		$a_01_2 = {6a 00 61 00 69 00 6c 00 6c 00 69 00 73 00 73 00 61 00 69 00 65 00 6e 00 74 00 20 00 61 00 64 00 6a 00 75 00 72 00 65 00 7a 00 20 00 64 00 61 00 72 00 64 00 65 00 72 00 } //01 00  jaillissaient adjurez darder
		$a_01_3 = {64 00 65 00 73 00 65 00 6e 00 67 00 6f 00 75 00 72 00 64 00 69 00 72 00 20 00 69 00 6d 00 70 00 61 00 72 00 74 00 69 00 61 00 75 00 78 00 } //01 00  desengourdir impartiaux
		$a_01_4 = {6e 72 34 41 44 6a 55 2b 64 47 74 6e 64 57 6b 41 63 47 6c 71 } //00 00  nr4ADjU+dGtndWkAcGlq
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 02 33 45 fc 8b 4d f8 89 01 c7 45 d0 16 00 00 00 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}