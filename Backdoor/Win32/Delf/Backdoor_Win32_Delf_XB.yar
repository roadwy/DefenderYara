
rule Backdoor_Win32_Delf_XB{
	meta:
		description = "Backdoor:Win32/Delf.XB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {32 32 32 2e 31 32 32 2e 90 10 03 00 2e 90 10 03 00 2f 64 6f 77 6e 6c 6f 61 64 2f 6d 6f 72 69 7a 2e 73 79 73 } //1
		$a_02_2 = {32 32 32 2e 31 32 32 2e 90 10 03 00 2e 90 10 03 00 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d } //1
		$a_02_3 = {32 32 32 2e 31 32 32 2e 90 10 03 00 2e 90 10 03 00 2f 61 63 63 65 73 73 5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d } //1
		$a_00_4 = {73 74 6f 70 5f 61 67 65 6e 74 2e 73 79 73 } //1 stop_agent.sys
		$a_00_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}