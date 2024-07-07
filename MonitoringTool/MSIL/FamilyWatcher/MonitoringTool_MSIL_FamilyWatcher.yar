
rule MonitoringTool_MSIL_FamilyWatcher{
	meta:
		description = "MonitoringTool:MSIL/FamilyWatcher,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 6d 00 69 00 6c 00 79 00 57 00 61 00 74 00 63 00 68 00 65 00 72 00 } //1 FamilyWatcher
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 } //1 Keylogger
		$a_01_2 = {73 00 68 00 72 00 65 00 65 00 54 00 65 00 6d 00 70 00 2e 00 74 00 69 00 66 00 } //1 shreeTemp.tif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}