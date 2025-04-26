
rule MonitoringTool_AndroidOS_MIPKO_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MIPKO.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 49 50 4b 4f 20 4d 4f 4e 49 54 4f 52 } //1 MIPKO MONITOR
		$a_01_1 = {45 6e 61 62 6c 65 4d 6f 6e 69 74 6f 72 } //1 EnableMonitor
		$a_01_2 = {45 6e 61 62 6c 65 43 6f 6e 74 61 63 74 73 } //1 EnableContacts
		$a_01_3 = {45 6e 61 62 6c 65 43 68 61 74 73 } //1 EnableChats
		$a_01_4 = {45 6e 61 62 6c 65 53 4d 53 } //1 EnableSMS
		$a_01_5 = {48 49 44 45 5f 50 41 53 53 57 4f 52 44 } //1 HIDE_PASSWORD
		$a_01_6 = {52 63 4f 74 67 43 6c 6c } //1 RcOtgCll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}