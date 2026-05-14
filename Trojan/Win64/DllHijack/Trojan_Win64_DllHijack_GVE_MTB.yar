
rule Trojan_Win64_DllHijack_GVE_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c1 0f 57 c0 f2 48 0f 2a c0 f2 0f 59 44 24 28 f2 0f 2c c0 89 45 83 48 63 44 24 20 44 8b 44 86 04 44 23 45 83 45 03 c0 48 63 44 24 20 8b 54 86 04 41 2b d0 03 54 24 48 48 63 44 24 20 89 54 86 04 } //1
		$a_01_1 = {f3 0f e6 c9 66 0f 6e c0 48 8b 43 08 48 39 03 f3 0f e6 c0 0f 94 c1 33 d2 f2 0f 58 c0 f2 0f 5c c8 0f 57 c0 f2 48 0f 2a c1 f2 0f 59 c8 f2 0f 11 4c 24 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}