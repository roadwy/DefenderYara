
rule TrojanSpy_AndroidOS_SpyAgent_L{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 4d 61 6e 61 67 65 72 73 2f 43 61 6c 6c 73 4d 61 6e 61 67 65 72 3b } //01 00  /Managers/CallsManager;
		$a_01_1 = {73 65 6e 64 56 6f 69 63 65 } //01 00  sendVoice
		$a_01_2 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 62 61 63 6b 20 63 61 6d 3a 3a 3a } //01 00  ==========back cam:::
		$a_01_3 = {67 65 74 41 6c 6c 54 65 6c 65 67 72 61 6d 46 69 6c 65 73 } //01 00  getAllTelegramFiles
		$a_01_4 = {67 65 74 56 6f 69 63 65 4e 6f 74 65 73 50 61 74 68 73 } //01 00  getVoiceNotesPaths
		$a_01_5 = {2f 53 65 72 76 69 63 65 2f 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 3b } //00 00  /Service/NotificationListener;
		$a_00_6 = {5d 04 00 } //00 1b 
	condition:
		any of ($a_*)
 
}