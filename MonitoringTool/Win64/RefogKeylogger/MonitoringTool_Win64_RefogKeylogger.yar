
rule MonitoringTool_Win64_RefogKeylogger{
	meta:
		description = "MonitoringTool:Win64/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 70 6b 36 34 2e 64 6c 6c } //01 00 
		$a_01_1 = {57 4d 5f 49 4d 48 4f 4f 4b 5f 4b 47 } //01 00 
		$a_01_2 = {57 4d 5f 4d 4f 55 53 45 4d 4f 56 45 48 4f 4f 4b 5f 4b 47 } //01 00 
		$a_01_3 = {52 65 66 6f 67 20 49 6e 63 } //04 00 
		$a_01_4 = {47 00 45 00 54 00 20 00 2f 00 69 00 6d 00 2f 00 73 00 65 00 6e 00 64 00 49 00 4d 00 3f 00 63 00 6f 00 6d 00 73 00 63 00 6f 00 72 00 65 00 43 00 68 00 61 00 6e 00 6e 00 65 00 6c 00 } //04 00 
		$a_01_5 = {3c 00 59 00 6d 00 73 00 67 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 22 00 36 00 22 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win64_RefogKeylogger_2{
	meta:
		description = "MonitoringTool:Win64/RefogKeylogger,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 3a 5c 50 72 6f 6a 65 63 74 73 5c 52 65 6c 65 61 73 65 52 65 70 6f 73 69 74 6f 72 79 5c 4d 6f 6e 69 74 6f 72 50 72 6f 6a 65 63 74 5c 44 65 6c 70 68 69 5c 44 69 73 74 72 5c 52 65 66 6f 67 4d 6f 6e 69 74 6f 72 5c 4d 70 6b 36 34 2e 70 64 62 } //01 00 
		$a_01_1 = {4d 00 55 00 54 00 45 00 58 00 5f 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 4d 00 5f 00 52 00 55 00 4e 00 4e 00 49 00 4e 00 47 00 3a 00 4d 00 50 00 4b 00 36 00 34 00 5f 00 4c 00 4f 00 41 00 44 00 45 00 52 00 } //00 00 
	condition:
		any of ($a_*)
 
}