
rule TrojanSpy_AndroidOS_SpyAgent_L{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6b 61 6d 72 61 6e 2e 68 75 6e 7a 61 6e 65 77 73 } //2 com.kamran.hunzanews
		$a_01_1 = {63 68 65 63 6b 69 6e 67 53 65 73 73 69 6f 6e 4d 61 6e 67 65 72 46 6f 72 55 70 6c 6f 61 64 69 6e 67 } //1 checkingSessionMangerForUploading
		$a_01_2 = {66 65 74 63 68 49 73 4d 65 73 73 61 67 65 73 41 64 64 65 64 } //1 fetchIsMessagesAdded
		$a_01_3 = {66 65 74 63 68 49 73 43 6f 6e 74 61 63 74 73 41 64 64 65 64 } //1 fetchIsContactsAdded
		$a_01_4 = {73 61 76 65 41 70 70 73 41 64 64 65 64 } //1 saveAppsAdded
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanSpy_AndroidOS_SpyAgent_L_2{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 4d 61 6e 61 67 65 72 73 2f 43 61 6c 6c 73 4d 61 6e 61 67 65 72 3b } //1 /Managers/CallsManager;
		$a_01_1 = {73 65 6e 64 56 6f 69 63 65 } //1 sendVoice
		$a_01_2 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 62 61 63 6b 20 63 61 6d 3a 3a 3a } //1 ==========back cam:::
		$a_01_3 = {67 65 74 41 6c 6c 54 65 6c 65 67 72 61 6d 46 69 6c 65 73 } //1 getAllTelegramFiles
		$a_01_4 = {67 65 74 56 6f 69 63 65 4e 6f 74 65 73 50 61 74 68 73 } //1 getVoiceNotesPaths
		$a_01_5 = {2f 53 65 72 76 69 63 65 2f 4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 3b } //1 /Service/NotificationListener;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}