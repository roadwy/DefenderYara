
rule TrojanSpy_Win32_Keylogger{
	meta:
		description = "TrojanSpy:Win32/Keylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 52 45 43 59 43 4c 45 52 5c 74 65 6d 70 30 31 2e 74 78 74 00 } //01 00 
		$a_01_1 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //01 00  [ENTER]
		$a_01_2 = {5b 00 42 00 4b 00 53 00 50 00 5d 00 } //01 00  [BKSP]
		$a_01_3 = {5b 00 49 00 4e 00 53 00 45 00 52 00 54 00 5d 00 } //01 00  [INSERT]
		$a_01_4 = {e9 52 02 00 00 83 ff 40 76 1b 83 ff 5b 73 16 6a 14 } //00 00 
		$a_00_5 = {7e 15 00 00 } //a2 3e 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Keylogger_2{
	meta:
		description = "TrojanSpy:Win32/Keylogger,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 6d 75 73 74 20 62 65 20 72 75 6e 20 75 6e 64 65 72 20 57 69 6e 33 32 5b 55 70 5d 00 } //01 00 
		$a_01_1 = {5b 4e 75 6d 20 4c 6f 63 6b 5d 00 } //01 00 
		$a_01_2 = {5b 25 73 20 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 5d } //01 00  [%s %d-%d-%d %d:%d:%d]
		$a_01_3 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d 00 } //01 00 
		$a_01_4 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d 00 } //01 00 
		$a_01_5 = {55 6e 6b 6f 77 6e 20 55 73 65 72 00 } //00 00  湕潫湷唠敳r
		$a_01_6 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}