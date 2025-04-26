
rule MonitoringTool_AndroidOS_TrackPlus_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TrackPlus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 68 6f 6e 65 74 72 61 63 6b 65 72 6f 66 66 69 63 69 61 6c 31 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 } //1 com/phonetrackerofficial1/BootReceiver
		$a_01_1 = {77 77 77 2e 70 68 6f 6e 65 74 72 61 63 6b 65 72 2e 63 6f 6d 2f 73 65 63 75 72 65 } //1 www.phonetracker.com/secure
		$a_01_2 = {73 70 79 54 72 61 63 6b 65 72 55 73 65 72 44 61 74 61 } //1 spyTrackerUserData
		$a_01_3 = {47 65 74 43 6f 6e 74 61 63 74 73 } //1 GetContacts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}