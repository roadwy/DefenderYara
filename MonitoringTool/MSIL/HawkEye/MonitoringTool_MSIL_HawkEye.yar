
rule MonitoringTool_MSIL_HawkEye{
	meta:
		description = "MonitoringTool:MSIL/HawkEye,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_01_0 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 HawkEye Keylogger
		$a_01_1 = {48 00 61 00 77 00 6b 00 53 00 70 00 79 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 73 00 } //1 HawkSpySoftwares
		$a_01_2 = {4b 00 65 00 79 00 53 00 74 00 72 00 6f 00 6b 00 65 00 20 00 4c 00 6f 00 67 00 73 00 } //1 KeyStroke Logs
		$a_01_3 = {43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 6f 00 67 00 73 00 } //1 Clipboard Logs
		$a_01_4 = {5b 00 59 00 45 00 53 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 5d 00 } //1 [YESStealer]
		$a_01_5 = {5b 00 42 00 6c 00 6f 00 63 00 6b 00 57 00 65 00 62 00 73 00 69 00 74 00 65 00 5d 00 } //1 [BlockWebsite]
		$a_01_6 = {5b 00 59 00 45 00 53 00 4b 00 65 00 79 00 53 00 74 00 72 00 6f 00 6b 00 65 00 5d 00 } //1 [YESKeyStroke]
		$a_01_7 = {5b 00 46 00 61 00 6b 00 65 00 4d 00 73 00 67 00 5d 00 } //1 [FakeMsg]
		$a_01_8 = {5b 00 59 00 45 00 53 00 53 00 63 00 72 00 65 00 65 00 6e 00 79 00 5d 00 } //1 [YESScreeny]
		$a_01_9 = {5b 00 59 00 45 00 53 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 5d 00 } //1 [YESClipboard]
		$a_01_10 = {5b 00 4e 00 4f 00 53 00 70 00 72 00 65 00 61 00 64 00 65 00 72 00 73 00 5d 00 } //1 [NOSpreaders]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=7
 
}