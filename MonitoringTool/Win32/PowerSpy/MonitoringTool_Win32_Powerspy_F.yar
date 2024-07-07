
rule MonitoringTool_Win32_Powerspy_F{
	meta:
		description = "MonitoringTool:Win32/Powerspy.F,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 70 00 73 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 } //1 \psappini.ini
		$a_01_1 = {70 00 73 00 61 00 70 00 70 00 69 00 6e 00 69 00 64 00 78 00 2e 00 69 00 6e 00 69 00 } //1 psappinidx.ini
		$a_01_2 = {62 00 64 00 6d 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //1 bdmreg.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}