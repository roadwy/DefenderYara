
rule MonitoringTool_AndroidOS_AndSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AndSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 6f 6f 6e 67 77 61 72 65 2e 63 6f 6d } //01 00  loongware.com
		$a_00_1 = {41 63 74 69 6f 6e 3d 43 68 65 63 6b 26 53 6f 66 74 4e 61 6d 65 3d 41 6e 64 53 70 79 26 52 65 67 43 6f 64 65 } //01 00  Action=Check&SoftName=AndSpy&RegCode
		$a_02_2 = {68 69 2e 62 61 69 64 75 2e 63 6f 6d 2f 66 69 6c 65 5f 63 6f 70 79 2f 62 6c 6f 67 2f 69 74 65 6d 2f 90 02 25 2e 68 74 6d 6c 90 00 } //01 00 
		$a_00_3 = {6d 6f 62 69 6c 65 6c 6f 67 67 65 72 2e 6e 65 74 } //01 00  mobilelogger.net
		$a_00_4 = {2f 6d 6c 2f 6d 61 6e 61 67 65 72 2f 75 70 6c 6f 61 64 2e 70 68 70 } //01 00  /ml/manager/upload.php
		$a_00_5 = {4d 79 53 65 6e 64 53 4d 53 } //01 00  MySendSMS
		$a_00_6 = {52 65 63 6f 72 64 43 61 6c 6c } //00 00  RecordCall
	condition:
		any of ($a_*)
 
}