
rule MonitoringTool_AndroidOS_PhoneSpy_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 79 3c 21 3e 36 70 70 2e 77 3c 21 3e 37 62 62 72 6f 77 73 3c 21 3e 37 72 } //1 com.spy<!>6pp.w<!>7bbrows<!>7r
		$a_01_1 = {73 6d 73 5f 70 68 6f 6e 3c 21 3e 37 5f 6c 3c 21 3e 38 73 74 } //1 sms_phon<!>7_l<!>8st
		$a_01_2 = {52 65 6d 6f 74 65 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 RemoteRecordingService
		$a_01_3 = {63 6f 6d 2f 73 70 61 5f 61 70 70 2f 61 6c 61 72 6d } //1 com/spa_app/alarm
		$a_01_4 = {73 3c 21 3e 37 6e 64 5f 64 3c 21 3e 36 74 3c 21 3e 36 5f 6e 3c 21 3e 37 77 2e 70 68 70 } //1 s<!>7nd_d<!>6t<!>6_n<!>7w.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}