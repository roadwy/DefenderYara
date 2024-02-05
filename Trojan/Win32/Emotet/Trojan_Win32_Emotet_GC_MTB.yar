
rule Trojan_Win32_Emotet_GC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 14 11 8b 4d 90 01 01 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 8b 3d 90 01 04 0f af 3d 90 01 04 8b 5d 90 01 01 03 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 8a 0c 18 8a 14 32 32 d1 8d 4c 24 90 01 01 51 88 13 90 00 } //01 00 
		$a_81_1 = {41 54 6e 2a 30 5a 24 57 58 23 30 6f 76 75 4b 4d 7b 38 48 61 75 30 69 33 70 65 57 63 52 6c 33 48 77 43 30 4c 3f 2a 4e 74 53 68 7b 72 70 6b 39 53 50 64 61 30 67 77 7a 77 31 35 67 52 32 64 64 65 61 52 42 31 2a 5a 3f 4e 4a 56 78 6d 50 4b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6b c6 44 24 90 01 01 65 c6 44 24 90 01 01 72 c6 44 24 90 01 01 6e c6 44 24 90 01 01 65 88 44 24 90 01 01 c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 90 02 19 ff d5 90 00 } //03 00 
		$a_02_1 = {6a 00 ff 15 90 02 19 c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 90 02 06 ff 90 00 } //03 00 
		$a_02_2 = {8b f8 53 8d 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 88 90 02 03 ff 90 00 } //01 00 
		$a_80_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}