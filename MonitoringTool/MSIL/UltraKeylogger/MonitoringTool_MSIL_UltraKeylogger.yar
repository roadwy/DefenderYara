
rule MonitoringTool_MSIL_UltraKeylogger{
	meta:
		description = "MonitoringTool:MSIL/UltraKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {55 00 6c 00 74 00 72 00 61 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Ultra Keylogger
		$a_03_1 = {1f 1d 0f 00 1a 28 90 01 01 00 00 06 90 00 } //01 00 
		$a_03_2 = {1f 1d 0f 01 1a 28 90 01 01 00 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}