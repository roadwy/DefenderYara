
rule TrojanSpy_Win32_Ursnif__Ursnif{
	meta:
		description = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 3d 25 75 26 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 63 72 63 3d 25 78 } //02 00 
		$a_00_1 = {40 53 4f 43 4b 53 3d 2a 40 } //01 00 
		$a_00_2 = {54 6f 72 43 6c 69 65 6e 74 } //01 00 
		$a_00_3 = {54 6f 72 43 72 63 } //01 00 
		$a_00_4 = {2e 6f 6e 69 6f 6e 2f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif__Ursnif_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 07 8b c8 74 90 01 01 85 c0 75 90 01 01 33 d2 42 eb 90 01 01 33 c3 33 45 90 01 01 83 c7 04 ff 45 90 01 01 8b d9 8a 4d 90 01 01 d3 c8 89 06 83 c6 04 4a 75 90 00 } //01 00 
		$a_00_1 = {2e 62 73 73 00 00 00 00 22 25 53 22 } //01 00 
		$a_03_2 = {3d 70 6e 6c 73 75 90 01 01 ff 73 90 01 01 03 d6 57 52 e8 90 00 } //01 00 
		$a_00_3 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 3a 24 00 00 0f b7 c9 03 d0 } //01 00 
		$a_03_4 = {c6 04 03 00 83 7e 10 04 72 90 01 01 8b 46 90 01 01 31 03 8b 45 90 01 01 8b 4d 90 01 01 89 18 8b 46 10 89 01 8b 44 24 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif__Ursnif_3{
	meta:
		description = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!C,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 6d 73 6c 30 } //01 00 
		$a_01_1 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04 } //01 00 
		$a_03_2 = {70 6e 6c 73 ff d6 89 45 90 01 01 3b c7 0f 84 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_3 = {8b 43 3c 03 c3 0f b7 50 06 6b d2 28 56 0f b7 70 14 81 f1 3a 24 00 00 0f b7 c9 03 d0 } //01 00 
		$a_03_4 = {c6 04 07 00 83 7e 10 04 72 90 01 01 8b 46 04 31 07 8b 45 90 01 01 8b 4d 90 01 01 89 38 8b 46 10 89 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}