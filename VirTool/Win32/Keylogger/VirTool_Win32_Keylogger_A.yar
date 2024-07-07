
rule VirTool_Win32_Keylogger_A{
	meta:
		description = "VirTool:Win32/Keylogger.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed } //1
		$a_03_1 = {83 f8 64 7f 5d 0f 84 90 01 01 00 00 00 83 f8 2e 7f 3b 0f 84 90 01 02 00 00 83 f8 0d 7f 19 0f 84 90 01 02 00 00 83 e8 09 0f 84 90 01 02 00 00 83 e8 03 90 00 } //1
		$a_03_2 = {83 c0 9b 83 f8 09 0f 87 90 01 02 00 00 ff 24 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}