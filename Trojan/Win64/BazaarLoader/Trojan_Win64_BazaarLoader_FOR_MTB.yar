
rule Trojan_Win64_BazaarLoader_FOR_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.FOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 74 24 10 48 89 7c 24 18 48 63 41 3c 8b f2 33 d2 44 8b 84 08 88 00 00 00 4c 8b c9 4c 03 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}