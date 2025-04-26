
rule MonitoringTool_Win32_HandyKeylogger{
	meta:
		description = "MonitoringTool:Win32/HandyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0c 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 44 55 43 45 44 20 42 59 20 48 41 4e 44 59 20 4b 45 59 4c 4f 47 47 45 52 20 4c 4f 47 20 50 41 52 53 45 52 } //1 PRODUCED BY HANDY KEYLOGGER LOG PARSER
		$a_01_1 = {57 69 64 65 53 74 65 70 20 53 6f 66 74 77 61 72 65 2e } //1 WideStep Software.
		$a_01_2 = {48 61 6e 64 79 20 4b 65 79 6c 6f 67 67 65 72 3a } //1 Handy Keylogger:
		$a_01_3 = {4b 65 79 6c 6f 67 67 65 72 27 73 20 74 68 72 65 61 64 73 20 73 68 75 74 20 64 6f 77 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 Keylogger's threads shut down successfully.
		$a_01_4 = {52 45 43 45 4e 54 20 4b 45 59 20 4c 4f 47 } //1 RECENT KEY LOG
		$a_01_5 = {53 50 59 4b 45 59 48 4f 4f 4b } //1 SPYKEYHOOK
		$a_01_6 = {48 57 5f 4b 45 59 42 4f 41 52 44 20 68 6f 6f 6b 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 2e } //1 HW_KEYBOARD hook installation successful.
		$a_01_7 = {48 57 5f 47 45 54 4d 45 53 53 41 47 45 20 68 6f 6f 6b 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 65 72 72 6f 72 2e } //1 HW_GETMESSAGE hook installation error.
		$a_01_8 = {53 70 79 53 79 73 4c 6f 67 3a } //1 SpySysLog:
		$a_01_9 = {73 75 70 70 6f 72 74 40 77 69 64 65 73 74 65 70 2e 63 6f 6d } //1 support@widestep.com
		$a_01_10 = {6f 6e 65 20 69 6e 73 74 61 6e 63 65 20 6f 66 20 74 68 65 20 48 61 6e 64 79 20 4b 65 79 6c 6f 67 67 65 72 20 63 61 6e 20 62 65 20 6c 61 75 6e 63 68 65 64 } //1 one instance of the Handy Keylogger can be launched
		$a_01_11 = {48 61 6e 64 79 20 4b 65 79 6c 6f 67 67 65 72 20 72 65 67 69 73 74 72 61 74 69 6f 6e 2e 2e 2e } //1 Handy Keylogger registration...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=4
 
}