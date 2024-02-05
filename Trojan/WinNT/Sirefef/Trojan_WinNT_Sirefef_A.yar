
rule Trojan_WinNT_Sirefef_A{
	meta:
		description = "Trojan:WinNT/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 06 56 01 00 c0 5f } //01 00 
		$a_01_1 = {8d 48 34 eb 02 33 c9 8b 44 24 08 85 c0 74 05 83 c0 34 eb 02 33 c0 6a 01 51 50 ff 15 } //01 00 
		$a_03_2 = {83 c3 f8 83 c7 02 90 01 01 c7 06 03 00 00 a0 66 89 5e 04 66 89 7e 0c ff 15 90 00 } //01 00 
		$a_01_3 = {5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_A_2{
	meta:
		description = "Trojan:WinNT/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 06 56 01 00 c0 5f } //01 00 
		$a_01_1 = {8d 48 34 eb 02 33 c9 8b 44 24 08 85 c0 74 05 83 c0 34 eb 02 33 c0 6a 01 51 50 ff 15 } //01 00 
		$a_03_2 = {83 c3 f8 83 c7 02 90 01 01 c7 06 03 00 00 a0 66 89 5e 04 66 89 7e 0c ff 15 90 00 } //01 00 
		$a_01_3 = {5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_A_3{
	meta:
		description = "Trojan:WinNT/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 5c 00 25 00 30 00 38 00 58 00 2e 00 78 00 38 00 36 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_00_1 = {3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 73 65 61 72 63 68 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e 3c 73 63 72 69 70 74 3e 6c 6f 63 61 74 69 6f 6e 2e 72 65 70 6c 61 63 65 28 22 25 73 22 29 3c 2f 73 63 72 69 70 74 3e } //01 00 
		$a_00_2 = {47 45 54 20 2f 73 65 61 72 63 68 3f 71 3d 25 53 20 48 54 54 50 2f 31 2e 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_A_4{
	meta:
		description = "Trojan:WinNT/Sirefef.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 5c 00 25 00 30 00 38 00 58 00 2e 00 78 00 38 00 36 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_1 = {3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 73 65 61 72 63 68 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e 3c 73 63 72 69 70 74 3e 6c 6f 63 61 74 69 6f 6e 2e 72 65 70 6c 61 63 65 28 22 25 73 22 29 3c 2f 73 63 72 69 70 74 3e } //01 00 
		$a_01_2 = {47 45 54 20 2f 73 65 61 72 63 68 3f 71 3d 25 53 20 48 54 54 50 2f 31 2e 31 } //00 00 
	condition:
		any of ($a_*)
 
}