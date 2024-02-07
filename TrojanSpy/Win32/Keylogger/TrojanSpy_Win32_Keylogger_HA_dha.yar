
rule TrojanSpy_Win32_Keylogger_HA_dha{
	meta:
		description = "TrojanSpy:Win32/Keylogger.HA!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 21 00 5d 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 70 00 61 00 73 00 74 00 65 00 } //01 00  [!]Clipboard paste
		$a_01_1 = {5b 00 2a 00 5d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 50 00 49 00 44 00 20 00 3e 00 20 00 25 00 64 00 3a 00 20 00 } //01 00  [*]Window PID > %d: 
		$a_01_2 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 68 00 6f 00 6f 00 6b 00 73 00 20 00 6f 00 6b 00 21 00 } //01 00  Install hooks ok!
		$a_01_3 = {77 68 61 74 65 76 65 72 } //01 00  whatever
		$a_01_4 = {25 00 6c 00 73 00 25 00 64 00 2e 00 7e 00 74 00 6d 00 70 00 } //01 00  %ls%d.~tmp
		$a_01_5 = {4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //00 00  KeyboardState
	condition:
		any of ($a_*)
 
}