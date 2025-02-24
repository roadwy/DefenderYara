
rule Trojan_Win32_Zusy_GC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 02 c3 90 13 32 c3 2a c3 90 13 32 c3 2a c3 90 13 c0 c8 78 aa 90 13 83 c1 ff 90 13 ac 02 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}