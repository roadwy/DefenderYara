
rule Trojan_Win32_Farfli_MAK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 8d 0c 06 0f b6 04 06 c1 e8 04 83 f8 09 7e 90 01 01 04 37 eb 90 01 01 04 30 88 02 8a 01 83 e0 0f 83 f8 09 7e 90 01 01 04 37 eb 90 01 01 04 30 88 42 01 46 42 42 3b 74 24 10 7c 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}