
rule Trojan_Win64_Emotet_RDC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb f7 eb 03 d3 ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1e 2b c8 48 8b 44 24 40 48 63 d1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}