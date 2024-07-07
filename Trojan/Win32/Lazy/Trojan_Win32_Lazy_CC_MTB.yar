
rule Trojan_Win32_Lazy_CC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 c1 34 0c c0 c8 07 04 21 04 21 2a c1 c0 c8 07 34 0c c0 c0 07 34 0c aa 4a 0f 85 } //1
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}