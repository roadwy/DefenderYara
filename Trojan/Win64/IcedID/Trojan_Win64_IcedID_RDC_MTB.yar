
rule Trojan_Win64_IcedID_RDC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 f8 04 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 89 c2 c1 e2 04 29 c2 89 c8 29 d0 48 63 d0 48 8b 45 e8 48 01 d0 0f b6 00 44 31 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}