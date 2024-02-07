
rule MonitoringTool_AndroidOS_Fmph_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Fmph.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 61 6e 67 6f 2e 66 69 6e 64 6d 79 70 68 6f 6e 65 } //01 00  com.mango.findmyphone
		$a_01_1 = {46 69 6e 64 4d 79 50 68 6f 6e 65 20 41 63 74 69 76 69 74 79 } //01 00  FindMyPhone Activity
		$a_01_2 = {73 69 6d 5f 63 61 72 64 5f 6d 6f 6e 69 74 6f 72 69 6e 67 5f 6f 6e } //01 00  sim_card_monitoring_on
		$a_01_3 = {41 6c 61 72 6d 5f 57 69 70 65 } //01 00  Alarm_Wipe
		$a_01_4 = {66 69 6e 64 6d 79 70 68 6f 6e 65 42 61 63 6b 43 61 6d 65 72 61 } //00 00  findmyphoneBackCamera
	condition:
		any of ($a_*)
 
}