
rule Trojan_Win32_Emotet_GOG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  01 00 
		$a_02_1 = {ff d6 33 f6 90 02 0c c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 02 03 78 c6 90 02 03 65 90 02 0f ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}