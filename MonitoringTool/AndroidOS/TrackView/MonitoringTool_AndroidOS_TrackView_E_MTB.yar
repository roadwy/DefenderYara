
rule MonitoringTool_AndroidOS_TrackView_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TrackView.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 41 63 74 69 76 69 74 79 } //1 CallActivity
		$a_01_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 4d 73 67 } //1 ConnectionMsg
		$a_01_2 = {74 72 61 63 6b 76 69 65 77 3a 2f 70 61 79 6d 65 6e 74 5f 72 65 73 75 6c 74 3f } //1 trackview:/payment_result?
		$a_01_3 = {61 70 70 2e 63 79 62 72 6f 6f 6b 2e 76 69 65 77 65 72 } //1 app.cybrook.viewer
		$a_01_4 = {63 6f 6d 2e 68 6f 6d 65 73 61 66 65 2e 73 65 6e 64 65 72 2e 4c 6f 67 69 6e 43 61 6c 6c 62 61 63 6b 41 63 74 69 76 69 74 79 } //1 com.homesafe.sender.LoginCallbackActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}