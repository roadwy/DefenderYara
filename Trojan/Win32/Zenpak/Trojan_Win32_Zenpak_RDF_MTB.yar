
rule Trojan_Win32_Zenpak_RDF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 38 83 f2 02 83 f2 04 89 e8 50 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}