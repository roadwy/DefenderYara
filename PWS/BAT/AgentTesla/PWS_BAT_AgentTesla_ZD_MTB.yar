
rule PWS_BAT_AgentTesla_ZD_MTB{
	meta:
		description = "PWS:BAT/AgentTesla.ZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4d 6f 76 65 54 6f 44 6f 63 75 6d 65 6e 74 45 6e 64 } //1 get_MoveToDocumentEnd
		$a_01_1 = {67 65 74 5f 44 65 6c 65 74 65 50 72 65 76 69 6f 75 73 57 6f 72 64 } //1 get_DeletePreviousWord
		$a_01_2 = {67 65 74 5f 53 65 6c 65 63 74 52 69 67 68 74 42 79 57 6f 72 64 } //1 get_SelectRightByWord
		$a_01_3 = {67 65 74 5f 4d 6f 76 65 44 6f 77 6e 42 79 50 61 67 65 } //1 get_MoveDownByPage
		$a_01_4 = {67 65 74 5f 44 65 63 72 65 61 73 65 4d 69 63 72 6f 70 68 6f 6e 65 56 6f 6c 75 6d 65 } //1 get_DecreaseMicrophoneVolume
		$a_01_5 = {67 65 74 5f 4d 6f 76 65 44 6f 77 6e 42 79 50 61 72 61 67 72 61 70 68 } //1 get_MoveDownByParagraph
		$a_01_6 = {4b 4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 53 74 75 64 69 6f 2e 45 64 69 74 6f 72 73 2e 53 65 74 74 69 6e 67 73 44 65 73 69 67 6e 65 72 2e 53 65 74 74 69 6e 67 73 53 69 6e 67 6c 65 46 69 6c 65 47 65 6e 65 72 61 74 6f 72 } //1 KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator
		$a_01_7 = {4d 79 2e 53 65 74 74 69 6e 67 73 } //1 My.Settings
		$a_01_8 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 20 4d 79 2e 4d 79 57 70 66 45 78 74 65 6e 73 74 69 6f 6e 4d 6f 64 75 6c 65 2e 57 69 6e 64 6f 77 73 } //1 Dispose__Instance__ My.MyWpfExtenstionModule.Windows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}