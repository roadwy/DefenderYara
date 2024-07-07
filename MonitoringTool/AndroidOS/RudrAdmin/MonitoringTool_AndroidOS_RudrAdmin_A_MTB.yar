
rule MonitoringTool_AndroidOS_RudrAdmin_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/RudrAdmin.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6c 6f 75 74 2f 63 6f 6d 2f 77 69 66 69 73 65 72 76 69 63 65 2f 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //1 Lclout/com/wifiservice/SplashActivity
		$a_00_1 = {46 61 6b 65 53 68 75 74 64 6f 77 6e 53 65 72 76 69 63 65 } //1 FakeShutdownService
		$a_00_2 = {46 61 6b 65 4c 61 75 6e 63 68 65 72 41 63 74 69 76 69 74 79 } //1 FakeLauncherActivity
		$a_00_3 = {73 74 61 72 74 4d 79 4f 77 6e 46 6f 72 65 67 72 6f 75 6e 64 } //1 startMyOwnForeground
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}