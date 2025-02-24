
rule Trojan_Win32_RedLine_RDFM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 8a 44 34 60 88 44 3c 60 88 4c 34 60 0f b6 44 3c 60 03 c2 89 74 24 38 0f b6 c8 89 4c 24 3c 84 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}