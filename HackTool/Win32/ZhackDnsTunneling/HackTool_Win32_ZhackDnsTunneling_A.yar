
rule HackTool_Win32_ZhackDnsTunneling_A{
	meta:
		description = "HackTool:Win32/ZhackDnsTunneling.A,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {64 00 2e 00 7a 00 68 00 61 00 63 00 6b 00 2e 00 63 00 61 00 } //01 00  d.zhack.ca
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  powershell.exe
		$a_00_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  cmd.exe
		$a_00_3 = {70 00 69 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //00 00  ping.exe
	condition:
		any of ($a_*)
 
}