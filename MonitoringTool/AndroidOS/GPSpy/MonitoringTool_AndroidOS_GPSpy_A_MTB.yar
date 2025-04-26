
rule MonitoringTool_AndroidOS_GPSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/GPSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 70 73 70 79 } //1 gpspy
		$a_00_1 = {4d 6f 62 69 6c 65 47 70 73 70 79 2e 63 6f 6d } //1 MobileGpspy.com
		$a_00_2 = {68 69 64 65 20 74 68 65 20 4d 6f 62 69 6c 65 2d 47 50 53 70 79 } //1 hide the Mobile-GPSpy
		$a_00_3 = {4c 63 6f 6d 2f 73 70 79 2f 53 65 6e 64 47 50 53 50 6f 73 69 74 69 6f 6e 73 } //1 Lcom/spy/SendGPSPositions
		$a_00_4 = {45 6e 61 62 6c 65 20 47 50 53 20 73 61 74 65 6c 6c 69 74 65 73 } //1 Enable GPS satellites
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}