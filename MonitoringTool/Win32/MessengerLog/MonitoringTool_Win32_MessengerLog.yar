
rule MonitoringTool_Win32_MessengerLog{
	meta:
		description = "MonitoringTool:Win32/MessengerLog,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 6d 00 6c 00 33 00 36 00 30 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 53 00 74 00 61 00 72 00 74 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } //01 00 
		$a_01_1 = {4d 4c 33 36 30 53 72 76 2e 49 53 65 72 76 43 6f 6e 74 72 6f 6c 6c 65 72 20 3d 20 73 20 27 49 53 65 72 76 43 6f 6e 74 72 6f 6c 6c 65 72 20 43 6c 61 73 73 27 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_MessengerLog_2{
	meta:
		description = "MonitoringTool:Win32/MessengerLog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 68 61 74 20 4c 6f 67 20 66 72 6f 6d 20 4d 65 73 73 65 6e 67 65 72 4c 6f 67 20 33 36 30 } //01 00 
		$a_01_1 = {28 4c 6f 67 55 70 6c 6f 61 64 65 72 3a 3a 55 70 6c 6f 61 64 4c 6f 67 29 20 43 68 61 74 20 6c 6f 67 20 75 70 6c 6f 61 64 20 66 61 69 6c 65 64 20 76 69 61 20 46 54 50 2e } //01 00 
		$a_01_2 = {28 43 68 61 74 4c 6f 67 32 3a 3a 57 72 69 74 65 4c 6f 67 29 20 43 61 6e 20 6e 6f 74 20 7a 69 70 20 66 69 6c 65 20 25 73 3a 20 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_MessengerLog_3{
	meta:
		description = "MonitoringTool:Win32/MessengerLog,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 00 25 00 73 00 6d 00 6c 00 33 00 36 00 30 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 53 00 74 00 61 00 72 00 74 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00 } //01 00 
		$a_01_1 = {4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 4c 00 6f 00 67 00 20 00 33 00 36 00 30 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00 } //01 00 
		$a_01_2 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 64 00 2c 00 20 00 54 00 49 00 44 00 3a 00 20 00 25 00 64 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}