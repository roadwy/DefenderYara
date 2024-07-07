
rule Trojan_Win32_Dialsnif_gen_B{
	meta:
		description = "Trojan:Win32/Dialsnif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_00_0 = {89 51 08 8a 08 80 f9 e8 75 0f 8b 48 01 8d 4c 19 05 2b c8 83 e9 05 89 48 01 } //3
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //1 OpenProcessToken
		$a_00_3 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //1 LookupPrivilegeValueA
		$a_00_4 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_6 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=9
 
}