
rule MonitoringTool_AndroidOS_MobileSpy{
	meta:
		description = "MonitoringTool:AndroidOS/MobileSpy,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6f 62 69 6c 65 4e 61 6e 6e 79 4c 6f 63 6b } //01 00  MobileNannyLock
		$a_01_1 = {73 68 6f 77 20 42 6c 6f 63 6b 20 6c 69 73 74 } //01 00  show Block list
		$a_01_2 = {6e 61 6e 6e 79 6c 6f 67 2e 74 78 74 } //01 00  nannylog.txt
		$a_01_3 = {75 70 6c 6f 61 64 69 6e 67 20 67 70 73 2d 2d 3e } //00 00  uploading gps-->
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_AndroidOS_MobileSpy_2{
	meta:
		description = "MonitoringTool:AndroidOS/MobileSpy,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 65 73 20 20 6e 6f 74 20 6d 61 74 63 68 2e 2e 21 21 50 6c 65 61 73 65 20 52 65 2d 65 6e 74 65 72 2e } //01 00  does  not match..!!Please Re-enter.
		$a_01_1 = {63 61 6c 6c 6c 6f 67 2e 70 68 70 3f } //01 00  calllog.php?
		$a_00_2 = {6d 6f 62 69 6c 65 73 70 79 } //01 00  mobilespy
		$a_01_3 = {72 65 6d 6f 76 65 20 74 68 65 73 65 20 70 65 6f 70 6c 65 3f } //00 00  remove these people?
	condition:
		any of ($a_*)
 
}