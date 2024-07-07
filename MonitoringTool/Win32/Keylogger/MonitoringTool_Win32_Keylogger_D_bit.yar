
rule MonitoringTool_Win32_Keylogger_D_bit{
	meta:
		description = "MonitoringTool:Win32/Keylogger.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 54 6f 6e 67 4b 65 79 4c 6f 67 67 65 72 90 02 20 53 4d 54 50 90 00 } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 74 61 74 75 73 3a 20 4d 61 69 6c 20 73 65 6e 74 20 73 75 63 63 65 73 73 2e } //1 Status: Mail sent success.
		$a_03_3 = {7b 42 61 63 6b 73 70 61 63 65 7d 90 02 10 7b 45 6e 74 65 72 7d 90 02 10 7b 53 70 61 63 65 7d 90 02 10 7b 50 72 69 6e 74 20 53 63 72 65 65 6e 7d 90 02 10 7b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 7d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}