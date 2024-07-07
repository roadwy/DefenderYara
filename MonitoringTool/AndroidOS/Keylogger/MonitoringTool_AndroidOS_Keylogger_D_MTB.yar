
rule MonitoringTool_AndroidOS_Keylogger_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Keylogger.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 44 65 74 65 63 74 6f 72 } //1 KeyDetector
		$a_01_1 = {43 6f 6e 74 61 63 74 73 44 69 63 74 69 6f 6e 61 72 79 } //1 ContactsDictionary
		$a_01_2 = {6b 65 79 2e 74 78 74 } //1 key.txt
		$a_01_3 = {63 6f 6d 2f 61 6e 64 72 6f 61 70 70 73 2f 6b 65 79 73 74 72 6f 6b 65 2f 6c 6f 67 67 65 72 } //1 com/androapps/keystroke/logger
		$a_01_4 = {61 75 74 6f 5f 64 69 63 74 2e 64 62 } //1 auto_dict.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}