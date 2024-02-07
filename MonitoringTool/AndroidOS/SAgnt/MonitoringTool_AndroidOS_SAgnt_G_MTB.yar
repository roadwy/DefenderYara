
rule MonitoringTool_AndroidOS_SAgnt_G_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SAgnt.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 6f 73 69 2e 61 6e 74 69 74 68 65 66 74 73 65 63 75 72 69 74 79 } //01 00  com.mosi.antitheftsecurity
		$a_01_1 = {4c 6f 67 63 61 6c 6c 53 65 72 76 69 63 65 } //01 00  LogcallService
		$a_01_2 = {53 65 63 72 65 74 43 61 6c 6c 52 65 63 65 69 76 65 72 } //01 00  SecretCallReceiver
		$a_01_3 = {77 69 70 65 64 61 74 61 } //01 00  wipedata
		$a_01_4 = {65 6e 61 62 6c 65 5f 64 65 74 65 63 74 69 76 65 } //00 00  enable_detective
	condition:
		any of ($a_*)
 
}