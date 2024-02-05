
rule Backdoor_Win32_Wepofoir_A{
	meta:
		description = "Backdoor:Win32/Wepofoir.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b7 48 06 39 4d f8 7d 28 8b 55 f8 6b d2 28 8b 45 f8 6b c0 28 8b 4d ec 8b 44 01 08 } //02 00 
		$a_01_1 = {02 04 0f 25 ff 00 00 00 89 c7 41 3b 4d 0c 75 05 b9 00 00 00 00 8b 44 bb 08 89 06 89 54 bb 08 83 45 f0 10 81 7d f0 00 04 00 00 } //01 00 
		$a_01_2 = {6b c9 14 8b 95 dc fb ff ff 83 7c 0a 04 05 0f 85 } //01 00 
		$a_01_3 = {75 4a 83 7d fc 40 7d 06 83 7d f0 00 7f 05 } //01 00 
		$a_01_4 = {83 7d fc 02 74 0b 83 7d fc 17 74 4e e9 92 00 00 00 } //01 00 
		$a_03_5 = {83 f9 20 74 0e 8b 95 90 01 02 ff ff 0f be 02 83 f8 09 75 1e 8b 8d 90 01 02 ff ff 0f be 11 85 d2 74 11 8b 85 90 01 02 ff ff 83 c0 01 89 85 90 01 02 ff ff eb c6 90 00 } //01 00 
		$a_01_6 = {63 73 63 72 69 70 74 20 2f 4e 6f 4c 6f 67 6f 20 2f 42 20 } //00 00 
	condition:
		any of ($a_*)
 
}