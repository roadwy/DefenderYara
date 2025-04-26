
rule MonitoringTool_AndroidOS_SpyPhone_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyPhone.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 47 65 74 53 70 79 50 68 6f 6e 65 46 75 6c 6c } //1 bGetSpyPhoneFull
		$a_01_1 = {2f 53 70 79 50 68 6f 6e 65 2f } //1 /SpyPhone/
		$a_01_2 = {48 69 64 65 53 61 76 65 64 4d 65 64 69 61 } //1 HideSavedMedia
		$a_01_3 = {73 70 79 70 68 6f 6e 65 5f 77 69 64 67 65 74 } //1 spyphone_widget
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}