
rule MonitoringTool_AndroidOS_Reptilic_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Reptilic.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 55 6e 68 69 64 65 41 70 70 } //01 00  hideUnhideApp
		$a_01_1 = {73 65 6e 64 5f 6f 6e 5f 63 68 61 6e 67 65 5f 73 69 6d } //05 00  send_on_change_sim
		$a_01_2 = {6e 65 74 2f 76 6b 75 72 68 61 6e 64 6c 65 72 2f 46 61 6b 65 41 63 74 69 76 69 74 79 } //01 00  net/vkurhandler/FakeActivity
		$a_01_3 = {69 6e 74 65 72 63 65 70 74 5f 61 64 64 65 64 5f 63 6f 6e 74 61 63 74 } //01 00  intercept_added_contact
		$a_01_4 = {41 64 64 49 6e 74 65 72 63 65 70 74 69 6f 6e 41 75 64 69 6f 50 61 74 68 41 63 74 69 76 69 74 79 } //01 00  AddInterceptionAudioPathActivity
		$a_01_5 = {72 65 63 6f 72 64 5f 65 6e 76 5f 61 66 74 65 72 5f 65 6e 64 5f 63 61 6c 6c } //00 00  record_env_after_end_call
	condition:
		any of ($a_*)
 
}