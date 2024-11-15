
rule Trojan_Win32_RedLine_RDFJ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 48 8a 44 04 4c 30 04 0a 41 89 4c 24 3c 3b 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}