
rule MonitoringTool_AndroidOS_Keylogger_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Keylogger.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4c 6f 67 67 65 72 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //1 KeyLoggerAccessibilityService
		$a_01_1 = {63 6f 6d 2f 67 70 6f 77 2f 61 6e 64 72 6f 69 64 6b 65 79 6c 6f 67 67 65 72 } //1 com/gpow/androidkeylogger
		$a_01_2 = {4b 65 79 4c 6f 67 67 65 72 2e 54 65 72 6d 73 41 67 72 65 65 64 } //1 KeyLogger.TermsAgreed
		$a_01_3 = {2f 6b 65 79 6c 6f 67 67 65 72 5f 74 65 78 74 5f } //1 /keylogger_text_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}