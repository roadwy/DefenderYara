
rule MonitoringTool_Win32_XPCSpyPro{
	meta:
		description = "MonitoringTool:Win32/XPCSpyPro,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 50 43 53 70 79 50 72 6f 5c 49 45 53 70 79 } //01 00  XPCSpyPro\IESpy
		$a_01_1 = {58 50 43 53 70 79 50 72 6f 5f 57 65 62 4d 61 69 6c } //01 00  XPCSpyPro_WebMail
		$a_01_2 = {49 4d 6f 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00  䵉湯搮汬䐀汬慃啮汮慯乤睯
	condition:
		any of ($a_*)
 
}