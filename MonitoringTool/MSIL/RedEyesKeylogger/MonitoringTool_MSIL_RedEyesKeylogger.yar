
rule MonitoringTool_MSIL_RedEyesKeylogger{
	meta:
		description = "MonitoringTool:MSIL/RedEyesKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 64 00 20 00 45 00 79 00 65 00 73 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Red Eyes Keylogger
		$a_01_1 = {55 00 70 00 6c 00 6f 00 61 00 64 00 20 00 6c 00 6f 00 67 00 20 00 74 00 6f 00 20 00 46 00 54 00 50 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 } //01 00  Upload log to FTP server:
		$a_01_2 = {52 00 75 00 6e 00 20 00 6f 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 3a 00 } //01 00  Run on Windows startup:
		$a_01_3 = {48 00 69 00 64 00 65 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //01 00  Hide process
		$a_01_4 = {2f 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 2f 00 70 00 72 00 74 00 73 00 63 00 72 00 2e 00 62 00 6d 00 70 00 } //00 00  /Picture/prtscr.bmp
		$a_00_5 = {5d 04 00 } //00 0b 
	condition:
		any of ($a_*)
 
}