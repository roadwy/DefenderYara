
rule MonitoringTool_AndroidOS_MissingDroid_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MissingDroid.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6d 73 4d 73 67 52 65 63 } //1 SmsMsgRec
		$a_00_1 = {73 65 6e 74 53 6d 73 4c 6f 63 61 74 69 6f 6e 46 6f 75 6e 64 } //1 sentSmsLocationFound
		$a_00_2 = {46 69 6e 64 4d 79 44 72 6f 69 64 } //1 FindMyDroid
		$a_00_3 = {53 6d 73 53 74 6f 6c 65 6e 4d 73 67 } //1 SmsStolenMsg
		$a_00_4 = {68 69 64 65 41 70 70 } //1 hideApp
		$a_00_5 = {66 72 69 65 6e 64 73 57 69 70 65 } //1 friendsWipe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}