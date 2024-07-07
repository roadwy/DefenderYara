
rule Trojan_Win32_Injector_TH_MTB{
	meta:
		description = "Trojan:Win32/Injector.TH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 5c 31 06 32 1c 11 80 e3 df 75 ed 49 75 f1 } //1
		$a_01_1 = {2b c3 8b c8 33 11 f7 c2 fe ff ff ff 74 0a } //1
		$a_01_2 = {44 65 62 75 67 67 65 72 20 20 20 64 65 74 65 63 74 65 64 21 20 20 20 44 6f 67 67 6f 6e 65 20 20 20 69 74 20 20 20 61 6c 6c 21 } //1 Debugger   detected!   Doggone   it   all!
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}