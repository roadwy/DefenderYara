
rule MonitoringTool_MSIL_Emissary{
	meta:
		description = "MonitoringTool:MSIL/Emissary,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 00 6d 00 69 00 73 00 73 00 61 00 72 00 79 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //10 Emissary Keylogger
		$a_01_1 = {63 00 68 00 6b 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 73 00 } //1 chkStealers
		$a_01_2 = {63 00 68 00 6b 00 41 00 6e 00 74 00 69 00 } //1 chkAnti
		$a_01_3 = {63 00 68 00 6b 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 } //1 chkStartup
		$a_01_4 = {63 00 68 00 6b 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //1 chkscreenshot
		$a_01_5 = {63 00 68 00 6b 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 } //1 chkdownloader
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}
rule MonitoringTool_MSIL_Emissary_2{
	meta:
		description = "MonitoringTool:MSIL/Emissary,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 00 20 00 45 00 6d 00 69 00 73 00 73 00 61 00 72 00 79 00 20 00 4c 00 6f 00 67 00 73 00 } //10 : Emissary Logs
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //1 DisableRegistryTools
		$a_01_2 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 77 00 77 00 77 00 2e 00 76 00 69 00 72 00 75 00 73 00 74 00 6f 00 74 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 127.0.0.1 www.virustotal.com
		$a_01_3 = {5c 00 53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //1 \Screenshot
		$a_01_4 = {6b 00 65 00 79 00 73 00 63 00 72 00 61 00 6d 00 62 00 6c 00 65 00 72 00 } //1 keyscrambler
		$a_01_5 = {6f 00 6c 00 6c 00 79 00 64 00 62 00 67 00 } //1 ollydbg
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}