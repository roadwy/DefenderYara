
rule Trojan_Win32_IcedID_GC_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f8 33 f9 c7 05 [0-30] 01 3d [0-30] 8b ff a1 [0-30] 8b 0d [0-30] 89 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}