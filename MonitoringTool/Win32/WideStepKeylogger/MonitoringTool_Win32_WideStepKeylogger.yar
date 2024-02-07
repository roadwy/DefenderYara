
rule MonitoringTool_Win32_WideStepKeylogger{
	meta:
		description = "MonitoringTool:Win32/WideStepKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 75 69 63 6b 4b 65 79 6c 6f 67 67 65 72 43 6c 61 73 73 } //01 00  QuickKeyloggerClass
		$a_01_1 = {4e 6f 77 2c 20 70 6c 65 61 73 65 2c 20 6c 61 75 6e 63 68 20 74 68 65 20 4b 65 79 6c 6f 67 67 65 72 20 66 6f 72 20 74 68 65 20 66 69 72 73 74 20 74 69 6d 65 2e } //01 00  Now, please, launch the Keylogger for the first time.
		$a_01_2 = {40 4b 65 79 6c 6f 67 67 65 72 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e } //00 00  @Keylogger installation complete.
	condition:
		any of ($a_*)
 
}