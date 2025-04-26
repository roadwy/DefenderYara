
rule MonitoringTool_MacOS_Spyrix_R_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.R!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 70 79 72 69 78 2e 6e 65 74 2f 75 73 72 2f 6d 6f 6e 69 74 6f 72 2f 67 65 74 73 65 74 74 69 6e 67 73 2e 70 68 70 } //1 spyrix.net/usr/monitor/getsettings.php
		$a_01_1 = {6d 6f 6e 69 74 6f 72 2f 69 75 70 6c 6f 61 64 2e 70 68 70 } //1 monitor/iupload.php
		$a_01_2 = {61 63 63 6f 75 6e 74 2f 63 68 65 63 6b 2d 73 75 62 73 63 72 69 70 74 69 6f 6e } //1 account/check-subscription
		$a_01_3 = {70 61 74 68 53 70 79 72 69 78 } //1 pathSpyrix
		$a_01_4 = {64 61 73 68 62 6f 61 72 64 2e 73 70 79 72 69 78 2e 63 6f 6d 2f } //1 dashboard.spyrix.com/
		$a_01_5 = {73 70 79 72 69 78 2e 6e 65 74 2f 75 73 72 2f 6d 6f 6e 69 74 6f 72 2f 75 70 6c 6f 61 64 5f 70 72 67 2e 70 68 70 } //1 spyrix.net/usr/monitor/upload_prg.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}