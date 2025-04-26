
rule TrojanSpy_Win32_Keylogger_FR{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 57 c6 85 ?? (fe|ff) ff ff 54 c6 85 ?? (fe|ff) ff ff 53 c6 85 ?? (fe|ff) ff ff 47 } //1
		$a_03_1 = {4a 79 05 ba 18 00 00 00 8a 44 ?? ?? 8a 1c 31 32 d8 88 1c 31 41 3b cf 7c e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanSpy_Win32_Keylogger_FR_2{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 fe e8 03 00 00 7d 17 e8 ?? ?? ?? ?? 99 b9 e8 03 00 00 f7 f9 46 89 14 b5 ?? ?? ?? ?? eb e1 } //1
		$a_03_1 = {89 06 83 c6 04 81 fe ?? ?? ?? ?? 7c ee be } //1
		$a_03_2 = {4a 79 05 ba 18 00 00 00 8a 44 ?? ?? 8a 1c 31 32 d8 88 1c 31 41 3b cf 7c e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}