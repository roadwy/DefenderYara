
rule Trojan_Win32_StealC_RDC_MTB{
	meta:
		description = "Trojan:Win32/StealC.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 30 04 0e 83 ff 0f 75 12 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}