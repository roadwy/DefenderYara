
rule Trojan_Win32_Piptea_F{
	meta:
		description = "Trojan:Win32/Piptea.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 79 37 9e c7 45 90 01 02 00 00 00 90 00 } //01 00 
		$a_03_1 = {8b 4d ec 03 48 28 89 4d 90 01 01 ff 55 90 01 01 c9 c3 90 00 } //01 00 
		$a_03_2 = {2b c1 89 45 ec 90 02 04 c1 e0 04 89 45 fc 8b 45 ec c1 e8 05 89 45 f0 90 02 04 ff 75 fc 90 00 } //01 00 
		$a_03_3 = {8d 04 81 50 e8 90 01 01 fe ff ff 83 c4 0c eb 90 01 01 c9 c3 90 00 } //01 00 
		$a_03_4 = {0f b6 40 02 85 c0 74 90 01 01 e9 90 01 02 00 00 90 00 } //02 00 
		$a_03_5 = {68 0c 30 3e 00 6a 01 e8 90 01 01 fb ff ff 83 c4 10 ff 75 ec 68 0c 30 3e 00 ff 75 f8 6a 0a 6a 0a e8 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}