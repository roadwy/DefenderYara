
rule Trojan_Win32_Alureon{
	meta:
		description = "Trojan:Win32/Alureon,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 44 24 1c 00 01 00 00 e8 90 01 02 00 00 83 c4 14 84 c0 74 30 a1 90 01 02 40 00 85 c0 74 27 8b 3d 90 01 02 40 00 b8 90 01 02 40 00 8b f0 8b 10 8d 44 24 0c 52 50 ff d7 90 00 } //01 00 
		$a_02_1 = {6a 3b 57 e8 90 01 02 00 00 8b f0 59 59 bb 90 01 02 40 00 80 26 00 46 89 3d 90 01 02 40 00 89 35 90 01 02 40 00 56 e8 90 01 02 ff ff 6a 2e 56 89 03 90 00 } //01 00 
		$a_02_2 = {c7 45 fc 00 01 00 00 f3 ab 66 ab aa 8d 45 fc 50 8d 85 fc fe ff ff 50 68 90 01 02 40 00 68 90 01 02 40 00 68 01 00 00 80 e8 90 01 02 00 00 83 c4 14 84 c0 74 2d 83 3d 90 01 02 40 00 00 74 24 b8 90 01 02 40 00 8b f0 ff 30 90 00 } //01 00 
		$a_02_3 = {0f 84 88 04 00 00 d1 e9 8d 56 0c 50 a1 90 01 04 51 52 53 ff 30 e8 90 01 02 ff ff 83 c4 14 85 c0 0f 95 c0 3a c3 0f 84 84 00 00 00 39 1e 75 0c c7 45 30 0f 00 00 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}