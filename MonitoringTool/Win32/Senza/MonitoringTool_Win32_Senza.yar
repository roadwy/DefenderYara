
rule MonitoringTool_Win32_Senza{
	meta:
		description = "MonitoringTool:Win32/Senza,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 65 6e 7a 61 6c 61 20 4b 65 79 6c 6f 67 67 65 72 } //01 00  Senzala Keylogger
		$a_01_1 = {54 65 63 6c 61 73 20 63 61 70 74 75 72 61 64 61 73 } //01 00  Teclas capturadas
		$a_01_2 = {57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 73 6b 79 70 65 2e 65 78 65 } //01 00  Windows Media Player\skype.exe
		$a_01_3 = {73 6d 74 70 2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d 2e 62 72 } //01 00  smtp.mail.yahoo.com.br
		$a_01_4 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //00 00  @hotmail.com
	condition:
		any of ($a_*)
 
}