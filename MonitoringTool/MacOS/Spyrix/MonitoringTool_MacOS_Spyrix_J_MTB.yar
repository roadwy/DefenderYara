
rule MonitoringTool_MacOS_Spyrix_J_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 63 74 75 61 6c 2e 61 6b 6d } //3 com.actual.akm
		$a_00_1 = {63 6f 6d 2e 73 70 79 72 69 78 2e 61 70 73 6b 6d } //3 com.spyrix.apskm
		$a_00_2 = {64 61 73 68 62 6f 61 72 64 2e 73 70 79 72 69 78 2e 63 6f 6d 2f } //1 dashboard.spyrix.com/
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 61 6b 6d 2f 53 70 79 72 69 78 2e 61 70 70 } //1 /Library/akm/Spyrix.app
		$a_00_4 = {70 61 74 68 53 70 79 72 69 78 } //1 pathSpyrix
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}