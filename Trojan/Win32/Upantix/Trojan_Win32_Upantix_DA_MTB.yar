
rule Trojan_Win32_Upantix_DA_MTB{
	meta:
		description = "Trojan:Win32/Upantix.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba 00 00 00 20 83 ea 01 75 fb 83 eb 01 75 f1 } //2
		$a_01_1 = {8b 45 f8 8b 5d d8 89 d9 29 c1 89 c8 83 c0 01 89 c2 8b 45 c8 39 c2 0f 85 } //2
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}