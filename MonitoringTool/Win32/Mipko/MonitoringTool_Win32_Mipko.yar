
rule MonitoringTool_Win32_Mipko{
	meta:
		description = "MonitoringTool:Win32/Mipko,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 00 45 00 46 00 4f 00 47 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 90 09 22 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}