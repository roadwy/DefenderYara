
rule Trojan_Win32_Stealer_CE_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 9d 06 00 00 74 12 40 3d 61 36 13 01 89 44 24 10 0f 8c } //1
		$a_01_1 = {8b 44 24 10 40 3d 95 6a 0e 00 89 44 24 10 0f 8c } //1
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}