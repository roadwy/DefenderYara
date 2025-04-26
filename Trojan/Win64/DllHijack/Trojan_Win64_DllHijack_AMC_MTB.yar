
rule Trojan_Win64_DllHijack_AMC_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b 44 24 20 4c 8d 4c 24 20 ba 01 00 00 00 48 8b cf ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}