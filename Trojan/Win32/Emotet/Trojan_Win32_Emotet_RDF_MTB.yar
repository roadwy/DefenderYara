
rule Trojan_Win32_Emotet_RDF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 17 8a 7c 0c 4f 80 c7 01 8b 54 24 28 8a 14 32 28 da 8b 7c 24 24 88 14 37 30 df 88 7c 0c 4f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}