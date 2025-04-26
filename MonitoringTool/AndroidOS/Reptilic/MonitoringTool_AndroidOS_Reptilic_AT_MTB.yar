
rule MonitoringTool_AndroidOS_Reptilic_AT_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Reptilic.AT!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 52 65 63 6f 72 64 41 63 74 69 76 69 74 79 } //1 CallRecordActivity
		$a_00_1 = {6e 65 74 2e 64 65 6c 70 68 69 62 6f 61 72 64 6c 61 79 65 72 2e 61 6e 64 72 6f 69 64 63 6f 72 65 61 70 70 } //1 net.delphiboardlayer.androidcoreapp
		$a_00_2 = {41 64 64 44 65 76 69 63 65 41 63 74 69 76 69 74 79 } //1 AddDeviceActivity
		$a_00_3 = {41 64 64 49 6e 74 65 72 63 65 70 74 69 6f 6e 50 68 6f 74 6f 50 61 74 68 41 63 74 69 76 69 74 79 } //1 AddInterceptionPhotoPathActivity
		$a_00_4 = {41 64 64 49 6e 74 65 72 63 65 70 74 69 6f 6e 41 75 64 69 6f 50 61 74 68 41 63 74 69 76 69 74 79 } //1 AddInterceptionAudioPathActivity
		$a_00_5 = {46 61 6b 65 41 63 74 69 76 69 74 79 } //1 FakeActivity
		$a_00_6 = {46 69 72 73 74 53 74 61 72 74 57 69 7a 61 72 64 41 63 74 69 76 69 74 79 } //1 FirstStartWizardActivity
		$a_00_7 = {69 6e 74 65 72 63 65 70 74 69 6f 6e 5f 6d 65 64 69 61 5f 77 68 61 74 73 61 70 70 } //1 interception_media_whatsapp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}