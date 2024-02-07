
rule MonitoringTool_AndroidOS_ShadSpy_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ShadSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 61 64 6f 77 2d 73 70 79 } //01 00  shadow-spy
		$a_01_1 = {49 6e 63 6f 6d 69 6e 67 53 6d 73 4c 6f 67 67 65 72 } //01 00  IncomingSmsLogger
		$a_01_2 = {43 6f 6e 74 61 63 74 4c 6f 67 67 65 72 2e 6a 61 76 61 } //01 00  ContactLogger.java
		$a_01_3 = {4e 65 77 43 61 6c 6c 46 69 6e 64 65 72 } //01 00  NewCallFinder
		$a_01_4 = {41 70 70 4c 6f 67 67 65 72 2e 6a 61 76 61 } //01 00  AppLogger.java
		$a_01_5 = {2f 64 61 74 61 73 74 6f 72 65 73 76 30 2e 64 62 } //00 00  /datastoresv0.db
	condition:
		any of ($a_*)
 
}