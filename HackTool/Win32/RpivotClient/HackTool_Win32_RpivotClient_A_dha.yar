
rule HackTool_Win32_RpivotClient_A_dha{
	meta:
		description = "HackTool:Win32/RpivotClient.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 79 49 6e 73 74 61 6c 6c 65 72 } //01 00  PyInstaller
		$a_01_1 = {63 6c 69 65 6e 74 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //01 00  client.exe.manifest
		$a_01_2 = {62 5f 68 61 73 68 6c 69 62 2e 70 79 64 } //01 00  b_hashlib.pyd
		$a_01_3 = {62 5f 73 6f 63 6b 65 74 2e 70 79 64 } //01 00  b_socket.pyd
		$a_01_4 = {62 5f 73 73 6c 2e 70 79 64 } //01 00  b_ssl.pyd
		$a_01_5 = {62 62 7a 32 2e 70 79 64 } //01 00  bbz2.pyd
		$a_01_6 = {62 73 65 6c 65 63 74 2e 70 79 64 } //01 00  bselect.pyd
		$a_01_7 = {62 75 6e 69 63 6f 64 65 64 61 74 61 2e 70 79 64 } //01 00  bunicodedata.pyd
		$a_01_8 = {62 77 69 6e 33 32 61 70 69 2e 70 79 64 } //01 00  bwin32api.pyd
		$a_01_9 = {62 77 69 6e 33 32 65 76 74 6c 6f 67 2e 70 79 64 } //01 00  bwin32evtlog.pyd
		$a_01_10 = {70 79 69 2d 77 69 6e 64 6f 77 73 2d 6d 61 6e 69 66 65 73 74 2d 66 69 6c 65 6e 61 6d 65 20 63 6c 69 65 6e 74 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //01 00  pyi-windows-manifest-filename client.exe.manifest
		$a_01_11 = {50 59 5a 2d 30 30 2e 70 79 7a } //00 00  PYZ-00.pyz
	condition:
		any of ($a_*)
 
}