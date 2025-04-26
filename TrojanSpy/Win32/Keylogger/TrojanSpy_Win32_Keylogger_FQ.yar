
rule TrojanSpy_Win32_Keylogger_FQ{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {18 00 00 00 8a ?? ?? 0c 8a 1c ?? 32 ?? 88 1c ?? ?? 3b ?? 7c e7 90 09 03 00 79 05 } //2
		$a_01_1 = {33 c9 3b fa c6 44 24 04 57 c6 44 24 06 6f } //1
		$a_03_2 = {83 fd 01 75 06 c6 ?? ?? 69 eb 2a 83 fd 02 75 06 c6 ?? ?? 64 eb 1f 83 fd 03 75 06 c6 ?? ?? 72 eb 14 } //1
		$a_03_3 = {03 c6 33 d2 f7 f1 33 c0 8a 82 d8 4d 41 00 33 d2 03 c3 03 d9 f7 74 24 ?? 8b 44 24 ?? 80 c2 ?? 88 54 2e ff 46 3b f7 7e d8 5b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}