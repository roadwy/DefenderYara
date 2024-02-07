
rule TrojanSpy_Win32_Keylogger_DA_bit{
	meta:
		description = "TrojanSpy:Win32/Keylogger.DA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 6b 65 79 6c 6f 67 5f 73 74 72 65 61 6d 5f 64 61 74 61 } //01 00  send_keylog_stream_data
		$a_01_1 = {73 65 6e 64 5f 73 68 65 6c 6c 5f 65 78 65 63 } //01 00  send_shell_exec
		$a_00_2 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //00 00  WebMonitor Client
	condition:
		any of ($a_*)
 
}