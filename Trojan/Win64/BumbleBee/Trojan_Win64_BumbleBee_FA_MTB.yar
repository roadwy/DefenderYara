
rule Trojan_Win64_BumbleBee_FA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 69 70 65 5c 62 6f 6f 73 74 5f 70 72 6f 63 65 73 73 5f 61 75 74 6f 5f 70 69 70 65 5f } //1 pipe\boost_process_auto_pipe_
		$a_01_1 = {73 79 73 5f 76 65 72 73 69 6f 6e } //1 sys_version
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 } //1 System32\wscript.exe
		$a_01_3 = {53 65 74 50 61 74 68 } //1 SetPath
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 50 72 6f 64 75 63 74 } //1 SELECT * FROM Win32_ComputerSystemProduct
		$a_01_5 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ProcessHacker.exe
		$a_01_6 = {6f 00 6c 00 6c 00 79 00 64 00 62 00 67 00 2e 00 65 00 78 00 65 00 } //1 ollydbg.exe
		$a_01_7 = {49 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ImmunityDebugger.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}