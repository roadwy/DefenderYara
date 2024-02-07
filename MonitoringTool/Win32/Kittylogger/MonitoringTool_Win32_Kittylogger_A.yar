
rule MonitoringTool_Win32_Kittylogger_A{
	meta:
		description = "MonitoringTool:Win32/Kittylogger.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 00 69 00 74 00 74 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 5b 00 } //01 00  Kitty Logger Started [
		$a_01_1 = {4b 00 4c 00 70 00 65 00 65 00 6b 00 2e 00 74 00 78 00 74 00 } //01 00  KLpeek.txt
		$a_01_2 = {42 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 5c 00 4b 00 69 00 74 00 74 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 4b 00 4c 00 2e 00 76 00 62 00 70 00 } //00 00  Business\Kitty Logger\KL.vbp
	condition:
		any of ($a_*)
 
}