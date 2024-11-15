
rule Trojan_AndroidOS_TrickMo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/TrickMo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6c 69 63 6b 65 72 53 65 6e 64 65 72 41 72 67 } //1 clickerSenderArg
		$a_01_1 = {67 65 74 53 74 61 72 74 4f 72 49 6e 73 74 61 6c 6c 50 61 63 6b 61 67 65 } //1 getStartOrInstallPackage
		$a_01_2 = {67 65 74 53 63 72 65 65 6e 49 6e 66 6f } //1 getScreenInfo
		$a_01_3 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //1 send_log_injects
		$a_01_4 = {52 65 63 6f 72 64 53 63 72 65 65 6e 55 74 69 6c } //1 RecordScreenUtil
		$a_01_5 = {6f 70 65 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 74 74 69 6e 67 73 4f 72 4d 65 73 73 61 67 65 } //1 openAccessibilitySettingsOrMessage
		$a_01_6 = {73 65 74 4e 65 65 64 4f 70 65 6e 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 74 74 69 6e 67 73 } //1 setNeedOpenAccessibilitySettings
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}