
rule Trojan_Win32_IcedID_GC_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f8 33 f9 c7 05 90 02 30 01 3d 90 02 30 8b ff a1 90 02 30 8b 0d 90 02 30 89 08 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}