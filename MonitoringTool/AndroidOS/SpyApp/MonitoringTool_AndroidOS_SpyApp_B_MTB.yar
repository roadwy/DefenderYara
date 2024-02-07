
rule MonitoringTool_AndroidOS_SpyApp_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyApp.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 61 69 74 53 63 72 65 65 6e 4f 6e 46 6f 72 52 65 63 6f 72 64 } //01 00  waitScreenOnForRecord
		$a_00_1 = {63 72 65 61 74 65 53 63 72 65 65 6e 43 61 70 74 75 72 65 49 6e 74 65 6e 74 } //01 00  createScreenCaptureIntent
		$a_00_2 = {73 74 6f 70 73 63 72 65 65 6e 73 68 61 72 69 6e 67 20 61 63 74 69 76 69 74 79 } //01 00  stopscreensharing activity
		$a_00_3 = {5f 53 6d 73 52 65 63 5f } //01 00  _SmsRec_
		$a_00_4 = {6e 6f 74 69 66 79 49 6e 43 61 6c 6c } //05 00  notifyInCall
		$a_00_5 = {73 70 79 61 70 70 2e } //01 00  spyapp.
		$a_00_6 = {75 6e 6c 6f 6f 6b 41 75 64 69 6f 43 61 6c 6c } //00 00  unlookAudioCall
	condition:
		any of ($a_*)
 
}