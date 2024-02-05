
rule Trojan_Win32_Emotet_JG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 64 89 0d 00 00 00 00 59 5f 5f 5e 5b 8b e5 5d 51 c3 8b 4d 90 02 02 33 cd e8 90 02 04 e9 90 00 } //01 00 
		$a_02_1 = {50 6a 00 6a 01 6a 00 8b 4d 90 02 02 51 ff 15 90 02 04 85 c0 75 04 32 c0 eb 02 b0 01 8b 4d 90 02 02 33 cd e8 90 02 04 8b e5 5d c3 90 00 } //01 00 
		$a_80_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  01 00 
		$a_80_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_JG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 90 01 02 ff 90 00 } //0a 00 
		$a_02_1 = {56 57 8b 7c 90 02 02 8b 90 01 01 8d 70 90 01 01 eb 90 01 01 8d 90 02 02 66 8b 90 02 04 66 85 90 01 01 75 90 01 01 2b 90 01 01 d1 90 01 01 8b 90 01 01 8b 90 01 01 33 90 01 01 f7 90 01 01 83 c1 01 8a 90 02 02 90 17 03 01 01 01 32 30 33 90 02 03 3b 90 01 06 5d c3 90 00 } //0a 00 
		$a_02_2 = {83 c1 01 8a 90 02 02 30 90 02 03 3b 90 02 06 5d c3 90 0a 40 00 8b 90 01 01 8d 70 90 01 01 eb 90 01 01 8d 90 02 02 66 8b 90 02 04 66 85 90 01 01 75 90 01 01 2b 90 01 01 d1 90 01 01 8b 90 01 01 8b 90 01 01 33 90 01 01 f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}