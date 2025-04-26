
rule MonitoringTool_MSIL_UltraKeylogger{
	meta:
		description = "MonitoringTool:MSIL/UltraKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 00 6c 00 74 00 72 00 61 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //2 Ultra Keylogger
		$a_03_1 = {1f 1d 0f 00 1a 28 ?? 00 00 06 } //1
		$a_03_2 = {1f 1d 0f 01 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}