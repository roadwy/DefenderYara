
rule MonitoringTool_Win32_PCAcme{
	meta:
		description = "MonitoringTool:Win32/PCAcme,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3c 6e 6f 74 6c 6f 67 67 65 64 3e } //02 00  <notlogged>
		$a_01_1 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //01 00  InternetGetConnectedState
		$a_01_2 = {69 73 20 50 43 20 41 63 6d 65 20 72 65 70 6f 72 74 } //01 00  is PC Acme report
		$a_01_3 = {50 43 20 41 63 6d 65 00 4b 45 52 4e 45 4c 33 32 } //01 00  䍐䄠浣e䕋乒䱅㈳
		$a_01_4 = {63 6f 70 79 20 6f 66 20 50 43 20 41 63 6d 65 } //00 00  copy of PC Acme
	condition:
		any of ($a_*)
 
}