
rule Trojan_Win64_BazaarLoader_TSC_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.TSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 cc 48 f7 e1 48 c1 ea 04 48 6b c2 ?? 48 2b c8 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4 44 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}