
rule MonitoringTool_Win32_StaffCop_A{
	meta:
		description = "MonitoringTool:Win32/StaffCop.A,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 61 70 74 75 72 65 46 69 6c 65 4d 6f 6e 69 74 6f 72 3a 20 5b 21 45 52 52 4f 52 21 5d } //05 00  CaptureFileMonitor: [!ERROR!]
		$a_01_1 = {43 00 61 00 70 00 74 00 75 00 72 00 65 00 46 00 69 00 6c 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 50 00 6f 00 72 00 74 00 } //05 00  CaptureFileMonitorPort
		$a_01_2 = {53 00 74 00 61 00 66 00 66 00 63 00 6f 00 70 00 } //00 00  Staffcop
	condition:
		any of ($a_*)
 
}