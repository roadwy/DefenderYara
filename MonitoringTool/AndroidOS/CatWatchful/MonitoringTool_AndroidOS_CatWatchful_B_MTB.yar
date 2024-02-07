
rule MonitoringTool_AndroidOS_CatWatchful_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CatWatchful.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 77 74 63 68 52 65 63 6f 72 64 41 75 64 69 6f } //01 00  swtchRecordAudio
		$a_00_1 = {57 74 73 70 43 68 61 74 4c 69 73 74 45 6c 65 6d 65 6e 74 } //01 00  WtspChatListElement
		$a_00_2 = {61 72 74 65 66 61 63 74 6f 73 2f 53 63 72 65 65 6e 43 61 70 74 75 72 } //01 00  artefactos/ScreenCaptur
		$a_00_3 = {44 65 74 65 63 74 61 47 70 73 4f 6e 4f 66 66 } //00 00  DetectaGpsOnOff
	condition:
		any of ($a_*)
 
}