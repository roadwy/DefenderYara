
rule MonitoringTool_Win32_Powerspy_F{
	meta:
		description = "MonitoringTool:Win32/Powerspy.F,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 70 00 73 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 } //01 00  \psappini.ini
		$a_01_1 = {70 00 73 00 61 00 70 00 70 00 69 00 6e 00 69 00 64 00 78 00 2e 00 69 00 6e 00 69 00 } //01 00  psappinidx.ini
		$a_01_2 = {62 00 64 00 6d 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //00 00  bdmreg.exe
	condition:
		any of ($a_*)
 
}