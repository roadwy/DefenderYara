
rule Trojan_Win32_Emotet_GGG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 0d 00 10 00 00 50 57 53 ff 15 90 02 04 50 ff 54 90 02 02 8b f0 3b f3 74 90 00 } //01 00 
		$a_00_1 = {57 56 83 e7 0f 83 e6 0f 3b fe 5e 5f } //01 00 
		$a_02_2 = {8b 06 8b 4d 90 02 02 5f 5e 64 90 02 02 00 00 00 00 5b c9 c2 90 00 } //01 00 
		$a_02_3 = {6a ff 50 64 90 02 02 00 00 00 00 50 8b 44 90 02 02 64 90 02 02 00 00 00 00 89 6c 90 02 02 8d 6c 90 02 02 50 c3 90 00 } //0a 00 
		$a_02_4 = {8b f8 53 8d 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 88 90 02 03 ff 90 00 } //0a 00 
		$a_80_5 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}