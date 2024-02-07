
rule Trojan_Win32_Emotet_L{
	meta:
		description = "Trojan:Win32/Emotet.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {52 53 44 53 90 02 15 6d 68 7a 33 70 2e 70 64 62 90 00 } //02 00 
		$a_02_1 = {52 53 44 53 90 02 15 67 72 72 2a 2a 30 28 31 73 2e 70 64 62 90 00 } //02 00 
		$a_02_2 = {58 49 70 6f 57 62 65 71 6f 62 4d 62 77 5a 50 68 90 02 20 6a 00 52 00 74 00 41 00 6b 00 43 00 62 00 72 00 78 00 7a 00 74 00 6e 00 68 00 72 00 78 00 6e 00 90 00 } //01 00 
		$a_00_3 = {67 70 6f 57 42 4f 49 49 68 64 54 6d 67 53 6b 57 } //01 00  gpoWBOIIhdTmgSkW
		$a_00_4 = {46 00 67 00 55 00 79 00 75 00 62 00 6a 00 65 00 54 00 69 00 46 00 71 00 51 00 6f 00 43 00 50 00 } //00 00  FgUyubjeTiFqQoCP
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_L_2{
	meta:
		description = "Trojan:Win32/Emotet.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 66 73 67 64 66 68 64 66 67 68 64 66 67 68 2e 6a 70 67 } //01 00  dfsgdfhdfghdfgh.jpg
		$a_01_1 = {47 43 54 4c 00 } //01 00 
		$a_03_2 = {50 ff 15 1c c0 00 03 81 ff 75 f7 0f 00 7e 90 02 09 81 fb 4f b7 23 00 74 0d 33 c0 81 7c 24 68 c5 90 90 0f 45 f0 47 85 f6 75 90 01 01 89 74 24 10 c7 44 24 10 90 01 02 ff 74 24 10 56 ff 15 14 c0 00 03 8b c8 89 0d 70 35 01 03 39 74 24 10 76 90 01 01 8b 3d 04 c0 00 03 90 00 } //01 00 
		$a_03_3 = {55 8b ec 51 53 8b d9 56 57 89 5d fc 8b 33 8b 53 04 e8 6a 00 00 00 8b f8 bb 20 00 00 00 0f 1f 00 8b ce 8b c6 c1 e9 05 03 0d 90 01 04 c1 90 01 02 03 05 90 01 04 33 c8 8d 90 01 02 33 c8 2b d1 8b ca 8b c2 c1 e9 05 03 0d 90 01 04 c1 e0 04 03 05 90 01 04 33 c8 8d 04 17 33 c8 8d bf 47 86 c8 61 2b f1 83 eb 01 75 b7 8b 5d fc 5f 89 33 5e 89 53 04 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_L_3{
	meta:
		description = "Trojan:Win32/Emotet.L,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 71 00 6b 00 53 00 4b 00 7a 00 51 00 61 00 6d 00 44 00 6b 00 73 00 75 00 59 00 67 00 75 00 } //01 00  sqkSKzQamDksuYgu
		$a_01_1 = {67 77 48 4a 6c 39 4c 4c 77 2e 70 64 62 } //00 00  gwHJl9LLw.pdb
	condition:
		any of ($a_*)
 
}