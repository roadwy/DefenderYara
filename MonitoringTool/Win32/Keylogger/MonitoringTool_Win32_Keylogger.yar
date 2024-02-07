
rule MonitoringTool_Win32_Keylogger{
	meta:
		description = "MonitoringTool:Win32/Keylogger,SIGNATURE_TYPE_PEHSTR_EXT,17 00 16 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 45 ff fe 00 eb d0 90 55 89 e5 83 ec 18 83 7d 08 01 74 08 83 7d 08 02 74 02 eb 0c c7 } //0a 00 
		$a_01_1 = {83 7d 08 01 74 08 83 7d 08 02 74 02 eb 0c c7 45 f8 00 00 00 00 e9 } //01 00 
		$a_01_2 = {5b 53 48 49 46 54 5d } //01 00  [SHIFT]
		$a_01_3 = {5b 43 4f 4e 54 52 4f 4c 5d } //01 00  [CONTROL]
		$a_01_4 = {5b 42 41 43 4b 53 50 41 43 45 5d } //01 00  [BACKSPACE]
		$a_00_5 = {4c 4f 47 2e 74 78 74 00 } //01 00  佌⹇硴t
		$a_01_6 = {6c 6f 67 53 79 73 74 65 6d 2e 74 78 74 00 } //01 00 
		$a_01_7 = {6c 6f 67 2e 64 69 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}