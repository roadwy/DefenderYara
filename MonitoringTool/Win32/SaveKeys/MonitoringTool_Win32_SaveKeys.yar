
rule MonitoringTool_Win32_SaveKeys{
	meta:
		description = "MonitoringTool:Win32/SaveKeys,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 3a 00 5c 00 53 00 4b 00 35 00 31 00 5c 00 4b 00 65 00 79 00 73 00 2e 00 76 00 62 00 70 00 00 00 } //1
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 53 4b 35 31 } //1 潍畤敬1䭓ㄵ
		$a_01_2 = {53 00 4b 00 35 00 31 00 20 00 77 00 61 00 73 00 20 00 } //1 SK51 was 
		$a_01_3 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}