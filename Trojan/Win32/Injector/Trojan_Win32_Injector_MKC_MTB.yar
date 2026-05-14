
rule Trojan_Win32_Injector_MKC_MTB{
	meta:
		description = "Trojan:Win32/Injector.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 94 6b cc 06 05 8b 6b cc 06 80 3b cc ?? ?? c6 03 00 bb 00 10 00 00 68 69 d1 8c 57 68 41 82 12 03 53 50 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}