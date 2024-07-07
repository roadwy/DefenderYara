
rule Backdoor_Win32_Agent_CF{
	meta:
		description = "Backdoor:Win32/Agent.CF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 31 31 35 2e 31 36 2e 37 39 2e 37 32 5c 61 62 63 64 24 } //1 \\115.16.79.72\abcd$
		$a_01_1 = {25 73 5c 74 65 72 6d 66 69 6c 65 2e 74 78 74 } //1 %s\termfile.txt
		$a_01_2 = {25 73 5c 64 69 73 61 62 6c 65 2e 74 78 74 } //1 %s\disable.txt
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_4 = {31 2e 62 61 74 } //1 1.bat
		$a_01_5 = {32 2e 62 61 74 } //1 2.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}