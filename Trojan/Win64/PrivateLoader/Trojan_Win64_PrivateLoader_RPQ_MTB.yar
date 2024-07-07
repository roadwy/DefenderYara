
rule Trojan_Win64_PrivateLoader_RPQ_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 c4 20 48 83 c9 ff ff d0 48 8b c3 b9 3c 03 00 00 80 00 08 e9 85 00 00 00 00 00 75 f4 ff d3 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}