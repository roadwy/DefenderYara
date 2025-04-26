
rule MonitoringTool_Win32_SpyRecon{
	meta:
		description = "MonitoringTool:Win32/SpyRecon,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 43 62 74 2e 64 6c 6c } //1 WinCbt.dll
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_2 = {5c 57 69 6e 43 62 74 5c 52 65 6c 65 61 73 65 5c 57 69 6e 43 62 74 2e 70 64 62 } //1 \WinCbt\Release\WinCbt.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_SpyRecon_2{
	meta:
		description = "MonitoringTool:Win32/SpyRecon,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {4b 62 64 48 6f 6f 6b 2e 64 6c 6c 00 [0-0f] 57 69 6e 43 62 74 2e 64 6c 6c 00 } //1
		$a_01_1 = {77 77 77 2e 31 2d 73 70 79 2e 63 6f 6d 00 } //1
		$a_01_2 = {31 2d 53 70 79 20 4d 6f 6e 69 74 6f 72 00 } //1 ⴱ灓⁹潍楮潴r
		$a_03_3 = {4b 65 79 6c 6f 67 67 65 72 52 65 70 6f 72 74 00 [0-0f] 57 65 62 6c 6f 67 52 65 70 6f 72 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}