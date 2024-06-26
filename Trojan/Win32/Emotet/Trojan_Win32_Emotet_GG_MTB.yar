
rule Trojan_Win32_Emotet_GG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 90 01 01 0f 90 01 04 30 90 01 03 3b 90 01 06 72 90 0a 71 00 8d 90 02 02 99 b9 90 01 04 f7 90 01 01 bf 90 01 05 8b 90 01 01 8b 90 01 03 03 90 01 01 99 f7 90 01 01 8a 90 01 03 8b da 8b 54 90 01 02 89 90 01 03 0f b6 d0 89 54 90 01 02 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 06 8b 4d 90 02 02 5f 5e 64 90 02 02 00 00 00 00 5b c9 c2 90 00 } //01 00 
		$a_02_1 = {6a ff 50 64 90 02 02 00 00 00 00 50 8b 44 90 02 02 64 90 02 02 00 00 00 00 89 6c 90 02 02 8d 6c 90 02 02 50 c3 90 00 } //01 00 
		$a_02_2 = {8d 4c 24 10 e8 90 02 1e ff 00 00 00 03 c1 b9 90 02 04 99 f7 f9 8d 4c 90 02 04 32 9c 14 90 00 } //01 00 
		$a_80_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GG_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 a1 00 00 00 00 50 83 ec 90 02 02 a1 90 02 04 33 c4 89 44 90 02 02 53 55 56 57 a1 90 02 04 33 c4 50 8d 44 90 02 02 64 90 02 01 00 00 00 00 90 00 } //01 00 
		$a_02_1 = {83 c4 04 0d 00 10 00 00 50 57 53 ff 15 90 02 04 50 ff 54 90 02 02 8b f0 3b f3 74 90 00 } //01 00 
		$a_00_2 = {57 56 83 e7 0f 83 e6 0f 3b fe 5e 5f } //01 00 
		$a_02_3 = {8b f8 53 8d 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 88 90 02 03 ff 90 00 } //01 00 
		$a_80_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GG_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 06 8b 4d 90 02 02 5f 5e 64 90 02 02 00 00 00 00 5b c9 c2 90 00 } //01 00 
		$a_02_1 = {6a ff 50 64 90 02 02 00 00 00 00 50 8b 44 90 02 02 64 90 02 02 00 00 00 00 89 6c 90 02 02 8d 6c 90 02 02 50 c3 90 00 } //01 00 
		$a_02_2 = {57 53 ff 15 90 02 04 8b f8 53 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 88 90 02 03 ff 90 00 } //01 00 
		$a_02_3 = {8a 03 88 45 90 02 02 ff 15 90 02 04 0f b6 90 02 02 0f b6 90 02 02 03 c1 8b ce 99 f7 f9 8a 84 90 02 06 32 45 90 02 02 88 03 43 ff 4d 90 02 02 75 90 00 } //01 00 
		$a_80_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GG_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 64 89 0d 00 00 00 00 59 5f 5f 5e 5b 8b e5 5d 51 c3 8b 4d 90 02 02 33 cd e8 90 02 04 e9 90 00 } //01 00 
		$a_02_1 = {64 a1 00 00 00 00 50 83 ec 90 02 02 a1 90 02 04 33 c4 89 44 90 02 02 53 55 56 57 a1 90 02 04 33 c4 50 8d 44 90 02 02 64 90 02 01 00 00 00 00 90 00 } //01 00 
		$a_02_2 = {53 8d 4c 24 90 02 03 51 90 02 07 c6 90 02 03 56 90 02 03 c6 90 02 03 69 90 02 03 c6 90 02 03 72 90 02 03 c6 90 02 03 74 90 02 03 c6 90 02 03 61 90 02 03 88 90 02 03 c6 90 02 03 41 90 02 03 88 90 02 03 88 90 02 03 c6 90 02 03 6f 90 02 03 c6 90 02 03 63 90 02 03 c6 90 02 03 45 90 02 03 c6 90 02 03 78 90 02 03 c6 90 02 03 4e 90 02 03 c6 90 02 03 6d 90 02 03 c6 90 02 03 61 90 02 03 88 90 00 } //01 00 
		$a_80_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}