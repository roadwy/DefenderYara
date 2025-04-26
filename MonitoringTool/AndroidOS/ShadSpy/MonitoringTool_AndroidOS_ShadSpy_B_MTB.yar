
rule MonitoringTool_AndroidOS_ShadSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ShadSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4d 61 6b 65 53 74 65 61 6c 74 68 41 63 74 69 76 69 74 79 } //1 MakeStealthActivity
		$a_00_1 = {43 61 6c 6c 4c 6f 67 67 65 72 } //1 CallLogger
		$a_00_2 = {6c 6f 67 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 } //1 logInstalledApps
		$a_00_3 = {63 6f 6e 74 61 63 74 20 74 72 61 63 6b 65 64 } //1 contact tracked
		$a_00_4 = {50 68 6f 74 6f 4c 6f 67 67 65 72 4f 62 73 65 72 76 65 72 } //1 PhotoLoggerObserver
		$a_00_5 = {4f 75 74 67 6f 69 6e 67 53 6d 73 4c 6f 67 67 65 72 } //1 OutgoingSmsLogger
		$a_00_6 = {73 68 61 64 6f 77 2d 73 70 79 } //1 shadow-spy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}