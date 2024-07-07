
rule MonitoringTool_Win32_ChatWatch{
	meta:
		description = "MonitoringTool:Win32/ChatWatch,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {59 00 61 00 68 00 6f 00 6f 00 20 00 4c 00 6f 00 67 00 73 00 } //2 Yahoo Logs
		$a_01_1 = {43 68 61 74 57 61 74 63 68 34 2e 54 72 61 79 49 63 6f 6e } //3 ChatWatch4.TrayIcon
		$a_00_2 = {54 00 68 00 65 00 20 00 63 00 68 00 61 00 74 00 20 00 6c 00 6f 00 67 00 73 00 20 00 61 00 72 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 74 00 6f 00 20 00 74 00 68 00 69 00 73 00 20 00 65 00 2d 00 6d 00 61 00 69 00 6c 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 } //2 The chat logs are attached to this e-mail message.
		$a_00_3 = {63 00 77 00 34 00 5f 00 6c 00 6f 00 67 00 5c 00 63 00 77 00 6c 00 6f 00 67 00 73 00 2e 00 69 00 6e 00 69 00 } //3 cw4_log\cwlogs.ini
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*3) >=6
 
}