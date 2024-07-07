
rule HackTool_Win32_Agent_A{
	meta:
		description = "HackTool:Win32/Agent.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 68 6f 6e 67 7a 68 69 2e 62 61 74 } //1 zhongzhi.bat
		$a_01_1 = {70 73 20 5c 5c } //1 ps \\
		$a_01_2 = {76 6e 63 2e 65 78 65 20 2d 64 } //1 vnc.exe -d
		$a_01_3 = {65 78 65 63 2e 62 61 74 } //1 exec.bat
		$a_01_4 = {72 61 64 6d 69 6e 2e 62 61 74 } //1 radmin.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}