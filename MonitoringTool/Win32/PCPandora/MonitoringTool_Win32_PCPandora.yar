
rule MonitoringTool_Win32_PCPandora{
	meta:
		description = "MonitoringTool:Win32/PCPandora,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 63 70 61 6e 64 6f 72 61 } //1 pcpandora
	condition:
		((#a_01_0  & 1)*1) >=1
 
}