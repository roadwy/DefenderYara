
rule TrojanSpy_Win32_Keylogger_FD{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FD,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 50 6c 61 79 57 6f 72 6b 00 } //05 00  捐汃敩瑮搮汬倀慬坹牯k
		$a_01_1 = {70 73 6b 65 79 2e 64 61 74 } //05 00  pskey.dat
		$a_01_2 = {43 61 70 74 75 72 65 00 } //05 00  慃瑰牵e
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 64 25 73 } //05 00  http://%s:%d/%d%s
		$a_01_4 = {50 72 6f 63 65 73 73 54 72 61 6e 73 } //01 00  ProcessTrans
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_6 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_7 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //01 00  GetKeyboardState
		$a_01_8 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //00 00  capCreateCaptureWindowA
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Keylogger_FD_2{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 61 79 57 6f 72 6b } //01 00  PlayWork
		$a_01_1 = {53 65 6c 66 20 44 65 6c 65 74 65 20 53 75 63 63 65 73 73 66 75 6c 6c 79 21 } //01 00  Self Delete Successfully!
		$a_01_2 = {22 25 73 22 20 2f 63 20 64 65 6c 20 22 25 73 22 } //01 00  "%s" /c del "%s"
		$a_01_3 = {5c 77 75 61 75 63 6c 74 2e 65 78 65 } //01 00  \wuauclt.exe
		$a_01_4 = {50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 00 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b 00 } //01 00  潐楬楣獥䍜浯汤㍧2潎湅楴敲敎睴牯k
		$a_01_5 = {50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b 00 00 4e 6f 43 6c 6f 73 65 00 4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 4e 6f 44 72 69 76 65 73 00 00 00 00 4e 6f 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}