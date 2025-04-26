
rule Trojan_Win32_Inject_CA_MTB{
	meta:
		description = "Trojan:Win32/Inject.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 d0 88 55 [0-04] 8b 4d [0-04] 03 4d [0-04] 8b 55 [0-04] 83 ea [0-04] 33 ca 66 89 4d } //1
		$a_03_1 = {03 d0 33 55 [0-04] 66 89 95 [0-04] eb 2a } //1
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}