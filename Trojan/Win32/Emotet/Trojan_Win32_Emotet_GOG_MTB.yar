
rule Trojan_Win32_Emotet_GOG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  1
		$a_02_1 = {ff d6 33 f6 [0-0c] c6 [0-03] 74 c6 [0-03] 61 c6 [0-03] 73 c6 [0-03] 6b c6 [0-03] 6d c6 [0-03] 67 c6 [0-03] 72 c6 [0-03] 2e c6 [0-03] 65 c6 [0-03] 78 c6 [0-03] 65 [0-0f] ff } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}