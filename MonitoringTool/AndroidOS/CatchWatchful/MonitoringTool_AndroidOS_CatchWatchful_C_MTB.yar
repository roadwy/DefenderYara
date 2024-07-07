
rule MonitoringTool_AndroidOS_CatchWatchful_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CatchWatchful.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 77 74 63 68 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //5 swtchScreenCapture
		$a_01_1 = {77 6f 73 63 2e 70 6c 61 79 2e 4c 61 75 6e 63 68 65 72 } //5 wosc.play.Launcher
		$a_01_2 = {43 61 74 57 61 74 63 68 66 75 6c } //5 CatWatchful
		$a_01_3 = {73 77 74 63 68 50 6c 61 79 53 74 6f 72 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 swtchPlayStoreNotifications
		$a_01_4 = {6c 61 73 74 4b 65 79 4c 6f 67 46 69 6c 65 4e 61 6d 65 } //1 lastKeyLogFileName
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}