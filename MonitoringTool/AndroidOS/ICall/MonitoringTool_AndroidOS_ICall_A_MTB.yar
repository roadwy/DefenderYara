
rule MonitoringTool_AndroidOS_ICall_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ICall.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 75 64 69 6f 4d 69 63 53 61 76 65 } //01 00  AudioMicSave
		$a_01_1 = {47 50 53 5f 47 45 54 } //01 00  GPS_GET
		$a_01_2 = {53 63 72 65 65 6e 4f 6e 52 65 63 65 69 76 65 72 } //01 00  ScreenOnReceiver
		$a_01_3 = {6f 75 74 54 65 6c 6e 6f } //01 00  outTelno
		$a_01_4 = {73 74 61 72 74 52 65 63 6f 64 69 6e 67 } //0a 00  startRecoding
		$a_01_5 = {63 6f 6d 2e 67 6f 6f 67 6c 65 2e 61 6e 64 72 6f 69 64 2e 73 73 6c } //0a 00  com.google.android.ssl
		$a_01_6 = {63 6f 6d 2e 67 6f 6f 67 6c 65 2e 73 73 6c } //00 00  com.google.ssl
	condition:
		any of ($a_*)
 
}