
rule TrojanSpy_Win32_Keylogger_O{
	meta:
		description = "TrojanSpy:Win32/Keylogger.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 68 66 66 66 66 a1 90 01 04 50 6a 00 6a 00 e8 90 00 } //01 00 
		$a_03_1 = {6a 5c 6a 08 0f b7 c6 50 6a 00 e8 90 01 04 68 90 01 04 6a 00 e8 90 00 } //01 00 
		$a_00_2 = {72 6f 75 74 65 20 64 65 6c 65 74 65 20 30 2e 30 2e 30 2e 30 } //00 00  route delete 0.0.0.0
	condition:
		any of ($a_*)
 
}