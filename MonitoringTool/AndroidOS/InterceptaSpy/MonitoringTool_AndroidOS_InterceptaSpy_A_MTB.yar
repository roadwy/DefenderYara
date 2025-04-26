
rule MonitoringTool_AndroidOS_InterceptaSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/InterceptaSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 2d 6d 65 61 73 75 72 65 6d 65 6e 74 2e 63 6f 6d } //1 app-measurement.com
		$a_00_1 = {6d 6f 62 69 6f 70 65 6e 2e 63 6f 6d 2f 72 65 63 65 69 76 65 72 2f 64 61 74 61 } //1 mobiopen.com/receiver/data
		$a_01_2 = {52 45 41 44 5f 43 41 4c 4c 5f 4c 4f 47 } //1 READ_CALL_LOG
		$a_00_3 = {6f 72 67 2f 77 65 62 72 74 63 2f 56 69 64 65 6f 43 61 70 74 75 72 65 72 } //1 org/webrtc/VideoCapturer
		$a_00_4 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //1 getLastKnownLocation
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}