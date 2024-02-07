
rule MonitoringTool_Win32_IMonitor{
	meta:
		description = "MonitoringTool:Win32/IMonitor,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6e 48 6f 6f 6b 57 65 62 4d 61 69 6c 43 6f 6d 70 6c 65 74 65 } //01 00  OnHookWebMailComplete
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 69 6d 6f 6e 61 67 65 6e 74 5c } //01 00  WINDOWS\SYSTEM32\drivers\imonagent\
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 54 48 43 5c 4f 75 74 44 65 76 69 63 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\THC\OutDevice
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 54 48 43 5c 4c 6f 67 53 65 74 74 69 6e 67 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\THC\LogSetting
		$a_01_4 = {69 70 73 65 63 63 6d 64 20 2d 77 20 52 45 47 20 2d 70 20 22 4c 6f 63 6b 4e 65 74 22 20 2d 72 20 22 50 61 73 73 20 34 38 32 30 22 20 2d 66 20 30 2b 2a 3a 34 38 32 30 3a 54 43 50 20 2d 6e 20 50 41 53 53 } //01 00  ipseccmd -w REG -p "LockNet" -r "Pass 4820" -f 0+*:4820:TCP -n PASS
		$a_03_5 = {c6 84 24 f0 02 00 00 19 e8 90 01 03 00 50 8d 4c 24 14 c6 84 24 e8 02 00 00 1a e8 90 01 03 00 8d 8c 24 a8 00 00 00 c6 84 24 e4 02 00 00 19 e8 90 01 03 00 8d 8c 24 88 00 00 00 c6 84 24 e4 02 00 00 15 90 00 } //00 00 
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}