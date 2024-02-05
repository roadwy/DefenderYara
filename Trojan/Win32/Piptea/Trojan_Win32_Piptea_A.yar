
rule Trojan_Win32_Piptea_A{
	meta:
		description = "Trojan:Win32/Piptea.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 08 ff 75 fc 90 02 08 8d 04 81 50 90 02 04 ff 30 e8 90 01 02 ff ff 83 c4 0c eb 90 00 } //01 00 
		$a_03_1 = {6a 08 8b 45 fc 90 02 08 8d 04 81 50 90 02 04 ff 30 e8 90 01 02 ff ff 83 c4 0c eb 90 00 } //01 00 
		$a_03_2 = {03 48 28 89 4d 90 01 01 ff 55 90 00 } //01 00 
		$a_03_3 = {0f b7 45 f0 6b c0 28 90 01 07 03 54 08 14 89 55 e0 ff 75 e8 ff 75 e0 ff 75 e4 90 01 04 00 83 c4 0c e9 90 01 01 ff ff ff 90 00 } //01 00 
		$a_03_4 = {c1 e9 05 03 0d 90 01 04 33 c1 90 02 04 2b c8 89 4d 90 02 05 c1 e0 04 03 05 90 00 } //01 00 
		$a_01_5 = {58 0f b6 40 02 85 c0 74 05 e9 } //00 00 
	condition:
		any of ($a_*)
 
}