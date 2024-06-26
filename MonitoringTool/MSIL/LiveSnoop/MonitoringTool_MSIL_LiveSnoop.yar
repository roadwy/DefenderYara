
rule MonitoringTool_MSIL_LiveSnoop{
	meta:
		description = "MonitoringTool:MSIL/LiveSnoop,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6c 00 69 00 76 00 65 00 73 00 6e 00 6f 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2f 00 70 00 6f 00 73 00 74 00 6c 00 6f 00 67 00 2e 00 70 00 68 00 70 00 } //01 00  https://livesnoop.com/client/postlog.php
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6c 00 69 00 76 00 65 00 73 00 6e 00 6f 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2f 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 73 00 2e 00 70 00 68 00 70 00 } //01 00  https://livesnoop.com/client/screenshots.php
		$a_01_2 = {6d 00 61 00 78 00 53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 73 00 50 00 65 00 72 00 4d 00 69 00 6e 00 75 00 74 00 65 00 3a 00 } //01 00  maxScreenshotsPerMinute:
		$a_01_3 = {57 00 65 00 62 00 63 00 61 00 6d 00 20 00 55 00 70 00 6c 00 6f 00 61 00 64 00 20 00 45 00 72 00 72 00 6f 00 72 00 3a 00 } //01 00  Webcam Upload Error:
		$a_01_4 = {4c 00 69 00 76 00 65 00 53 00 6e 00 6f 00 6f 00 70 00 5f 00 41 00 67 00 65 00 6e 00 74 00 } //00 00  LiveSnoop_Agent
		$a_00_5 = {5d 04 00 } //00 4e 
	condition:
		any of ($a_*)
 
}