
rule Trojan_Win32_Stealer_CF_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 fe 43 d0 bc 00 7d 08 57 57 ff 15 90 02 04 81 fe e5 e7 0c 09 7f 09 46 81 fe 7a c0 7c 70 7c df 90 00 } //1
		$a_03_1 = {81 f9 16 76 00 00 75 05 e8 90 02 04 41 81 f9 e9 66 24 00 7c ea 90 00 } //1
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}