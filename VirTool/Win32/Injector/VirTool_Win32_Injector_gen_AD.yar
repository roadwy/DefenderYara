
rule VirTool_Win32_Injector_gen_AD{
	meta:
		description = "VirTool:Win32/Injector.gen!AD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {8a 08 8b 55 0c 03 55 f4 33 c0 8a 02 8b 55 f8 6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 4d fc } //3
		$a_01_1 = {b8 68 58 4d 56 } //1
		$a_08_2 = {64 6f 20 64 65 6c 20 22 25 73 22 20 26 26 20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 70 69 6e 67 } //4 do del "%s" && if exist "%s" ping
		$a_08_3 = {54 68 65 20 57 69 72 65 73 68 61 72 6b 20 4e 65 74 77 6f 72 6b 20 41 6e 61 6c 79 7a 65 72 } //1 The Wireshark Network Analyzer
		$a_08_4 = {2d 20 53 79 73 69 6e 74 65 72 6e 61 6c 73 3a 20 77 77 77 2e 73 79 73 69 6e 74 65 72 6e 61 6c 73 2e 63 6f 6d } //1 - Sysinternals: www.sysinternals.com
		$a_08_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_08_6 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_08_7 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_08_2  & 1)*4+(#a_08_3  & 1)*1+(#a_08_4  & 1)*1+(#a_08_5  & 1)*1+(#a_08_6  & 1)*1+(#a_08_7  & 1)*1) >=6
 
}