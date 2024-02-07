
rule TrojanSpy_AndroidOS_SmForw_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 65 66 65 6e 64 65 72 2e 70 6c 75 67 69 6e 2e 46 69 72 73 74 52 75 6e 6e 61 62 6c 65 } //01 00  com.defender.plugin.FirstRunnable
		$a_01_1 = {64 65 66 65 6e 64 65 72 5f 70 6c 75 67 69 6e 2e 6a 61 72 } //01 00  defender_plugin.jar
		$a_01_2 = {2e 73 74 72 65 61 6d 7c 6d 6f 64 74 31 } //01 00  .stream|modt1
		$a_01_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //01 00  setComponentEnabledSetting
		$a_01_4 = {64 65 76 69 63 65 5f 70 6f 6c 69 63 79 } //00 00  device_policy
	condition:
		any of ($a_*)
 
}