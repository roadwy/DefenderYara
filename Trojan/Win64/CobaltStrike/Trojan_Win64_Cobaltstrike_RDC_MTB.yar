
rule Trojan_Win64_Cobaltstrike_RDC_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 01 48 8b 4c 24 40 48 8b 54 24 28 0f be 0c 11 33 c8 8b c1 8b 4c 24 20 48 8b 54 24 40 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}