
rule Trojan_Win32_DarkGate_GC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d2 f7 f3 8a 04 16 30 04 0f } //1
		$a_01_1 = {41 89 c8 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_DarkGate_GC_MTB_2{
	meta:
		description = "Trojan:Win32/DarkGate.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c7 f7 a4 9e e9 00 00 00 00 e8 69 07 00 00 0b 6c 63 6c 48 d7 57 ad d2 84 3c 15 62 30 cb 30 f3 30 98 64 84 64 10 64 f1 64 71 29 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}