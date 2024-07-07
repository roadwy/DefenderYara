
rule MonitoringTool_AndroidOS_SMSSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SMSSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 68 6f 77 53 70 79 44 69 61 6c 6f 67 } //1 showSpyDialog
		$a_00_1 = {73 6d 73 73 70 79 4c 6f 63 6b 3a } //1 smsspyLock:
		$a_00_2 = {73 70 79 76 69 65 77 5f 65 6d 61 69 6c } //1 spyview_email
		$a_00_3 = {73 6d 73 20 72 65 74 75 72 6e 20 69 6e 20 53 4d 53 55 74 69 6c } //1 sms return in SMSUtil
		$a_00_4 = {73 70 79 20 73 65 72 76 69 63 65 20 73 74 61 72 74 73 } //1 spy service starts
		$a_00_5 = {54 68 69 73 20 69 73 20 53 4d 53 20 53 70 79 2e 20 49 74 20 6a 75 73 74 20 6c 6f 6f 6b 73 20 6c 69 6b 65 20 61 20 54 69 70 20 43 61 6c 63 75 6c 61 74 6f 72 } //1 This is SMS Spy. It just looks like a Tip Calculator
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}