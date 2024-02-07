
rule Trojan_Win32_Qakbot_BS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e9 15 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 00 } //01 00 
		$a_02_1 = {eb 00 8b 65 90 01 01 58 8b e8 8b 15 90 01 04 52 8b 15 90 01 04 52 8b 15 90 01 04 ff e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 11 44 24 04 8d 44 24 04 50 51 01 f9 ff d1 85 ff 74 90 01 01 b9 90 01 04 03 4c 24 08 6a 40 51 8b 7c 24 44 ff 77 20 6a 00 ff d0 90 00 } //01 00 
		$a_00_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //01 00  DrawThemeIcon
		$a_00_2 = {6d 66 69 78 61 75 74 6f 75 74 69 6c 34 2e 64 6c 6c } //00 00  mfixautoutil4.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BS_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ec 31 18 68 90 02 04 e8 90 02 04 8b d8 8b 45 e8 83 c0 04 03 d8 68 90 02 04 e8 90 02 04 2b d8 68 90 02 04 e8 90 02 04 03 d8 68 90 02 04 e8 90 02 04 2b d8 89 5d e8 68 90 02 04 e8 90 02 04 8b d8 8b 45 ec 83 c0 04 03 d8 68 90 02 04 e8 90 02 04 2b d8 89 5d ec 8b 45 e8 3b 45 e4 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BS_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e9 01 89 0d 90 01 04 8b 0d 90 01 04 83 c1 01 a1 90 01 04 a3 90 01 04 a1 90 01 04 31 0d 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //01 00 
		$a_02_1 = {03 f0 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8a 0c 31 88 0c 10 8b 55 90 01 01 83 c2 01 89 55 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 fe 81 e6 ff 00 00 00 8b 7d 90 01 01 8a 0c 37 8b 75 90 01 01 8b 7d 90 01 01 32 0c 3e 8b 75 90 01 01 88 0c 3e 66 c7 45 90 01 01 c5 b4 83 c7 01 8b 75 90 01 01 39 f7 90 00 } //01 00 
		$a_02_1 = {89 14 24 8b 54 24 90 01 01 8a 0c 11 31 de 89 74 24 90 01 01 8b 74 24 90 01 01 8b 5c 24 90 01 01 32 0c 1e 8b 54 24 90 01 01 8b 74 24 90 01 01 88 0c 32 90 00 } //01 00 
		$a_02_2 = {01 d8 8b 5c 24 90 01 01 8a 14 33 88 c6 0f b6 c6 8b 74 24 90 01 01 8a 34 06 30 d6 8b 44 24 90 01 01 89 84 24 90 01 04 8b 44 24 1c 89 84 24 90 01 04 8b 44 24 90 01 01 88 34 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BS_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b f2 71 89 cf 01 f7 6b f2 71 89 cb 01 f3 83 c3 6d 6b f2 71 89 44 24 30 89 c8 01 f0 83 c0 0d 8b 00 6b f2 71 01 f1 83 c1 11 8b 09 33 0b 8b 74 24 78 89 f3 03 5c 24 7c 89 44 24 2c 8b 44 24 30 2b 07 8b 7c 24 2c 01 c7 } //00 00 
	condition:
		any of ($a_*)
 
}