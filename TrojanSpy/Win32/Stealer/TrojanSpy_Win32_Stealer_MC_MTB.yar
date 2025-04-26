
rule TrojanSpy_Win32_Stealer_MC_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {c7 05 9c d7 48 00 01 00 00 00 8a 4d 10 88 0d 98 d7 48 00 83 7d 0c 00 75 4c 83 3d 94 f1 48 00 00 74 31 8b 15 90 f1 48 00 83 ea 04 89 15 90 f1 48 00 a1 90 f1 48 00 3b 05 94 f1 48 00 72 15 8b 0d 90 f1 48 00 83 39 00 74 08 8b 15 90 f1 48 00 ff 12 eb cf } //1
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_3 = {44 65 62 75 67 42 72 65 61 6b } //1 DebugBreak
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}