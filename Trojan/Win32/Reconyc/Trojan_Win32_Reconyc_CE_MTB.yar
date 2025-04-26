
rule Trojan_Win32_Reconyc_CE_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 75 28 8d 45 f0 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c 50 } //1
		$a_01_1 = {51 ff 75 1c 56 53 ff 75 10 ff 75 0c } //1
		$a_01_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 46 75 6e 31 2e 64 6c 6c } //1 C:\windows\system32\Fun1.dll
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}