
rule MonitoringTool_AndroidOS_NeoSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/NeoSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 73 74 72 6f 6b 65 73 4f 6e } //1 keystrokesOn
		$a_01_1 = {52 6f 6f 74 53 63 72 65 65 6e 73 68 6f 74 53 65 72 76 69 63 65 } //1 RootScreenshotService
		$a_01_2 = {4b 65 79 4c 6f 67 67 67 65 72 } //1 KeyLoggger
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 /system/bin/screencap -p
		$a_01_4 = {73 65 6e 64 50 68 6f 74 6f 53 63 72 65 65 6e } //1 sendPhotoScreen
		$a_00_5 = {63 6f 6d 2e 6e 73 6d 6f 6e 2e 67 75 61 72 64 } //1 com.nsmon.guard
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}