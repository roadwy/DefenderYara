
rule MonitoringTool_MacOS_Veriato_A_MTB{
	meta:
		description = "MonitoringTool:MacOS/Veriato.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 66 69 67 2f 45 6d 61 69 6c 49 6e 66 6f 2f 55 73 65 72 73 2f 55 73 65 72 } //1 config/EmailInfo/Users/User
		$a_00_1 = {49 43 68 61 74 49 6e 66 6f 2f 6c 61 73 74 50 72 6f 63 65 65 64 54 69 6d 65 } //1 IChatInfo/lastProceedTime
		$a_00_2 = {2f 63 61 70 74 75 72 65 55 72 6c } //1 /captureUrl
		$a_00_3 = {2e 2f 62 6c 75 65 70 72 69 6e 74 73 65 63 69 64 } //1 ./blueprintsecid
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}