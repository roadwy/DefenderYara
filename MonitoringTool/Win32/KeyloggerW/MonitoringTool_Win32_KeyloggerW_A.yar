
rule MonitoringTool_Win32_KeyloggerW_A{
	meta:
		description = "MonitoringTool:Win32/KeyloggerW.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 74 61 73 6b 73 5c 69 6e 64 65 78 2e 64 61 74 } //1 \tasks\index.dat
		$a_01_1 = {54 74 6c 65 3a 20 25 73 } //1 Ttle: %s
		$a_01_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \CurrentVersion\Run
		$a_01_3 = {57 73 63 6e 74 66 79 } //1 Wscntfy
		$a_01_4 = {5b 52 69 67 68 74 5d } //1 [Right]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}