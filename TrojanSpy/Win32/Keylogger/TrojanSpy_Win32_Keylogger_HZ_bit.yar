
rule TrojanSpy_Win32_Keylogger_HZ_bit{
	meta:
		description = "TrojanSpy:Win32/Keylogger.HZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 57 00 65 00 71 00 77 00 64 00 71 00 77 00 64 00 64 00 31 00 64 00 31 00 32 00 } //01 00  EWeqwdqwdd1d12
		$a_01_1 = {2f 00 6c 00 6f 00 67 00 2e 00 70 00 68 00 70 00 } //01 00  /log.php
		$a_01_2 = {3e 00 3c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 3a 00 } //01 00  ><Process:
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}