
rule MonitoringTool_Win32_SCKeylog_bit{
	meta:
		description = "MonitoringTool:Win32/SCKeylog!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 2d 00 43 00 65 00 6e 00 74 00 72 00 61 00 6c 00 27 00 73 00 20 00 53 00 43 00 2d 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 } //01 00  Soft-Central's SC-KeyLog
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 53 6f 66 74 43 65 6e 74 72 61 6c 5c 53 43 2d 4b 65 79 4c 6f 67 } //01 00  Software\SoftCentral\SC-KeyLog
		$a_01_2 = {58 2d 4d 61 69 6c 65 72 3a 20 53 43 2d 4b 4c 20 4d 61 69 6c 20 73 65 72 76 69 63 65 } //01 00  X-Mailer: SC-KL Mail service
		$a_01_3 = {4f 00 70 00 65 00 6e 00 20 00 53 00 43 00 2d 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 20 00 68 00 6f 00 6d 00 65 00 70 00 61 00 67 00 65 00 } //00 00  Open SC-KeyLog homepage
	condition:
		any of ($a_*)
 
}