
rule Trojan_Win64_BazaarLoader_TSP_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.TSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 cd 48 f7 e1 48 c1 ea ?? 48 6b c2 16 48 2b c8 8a 44 0c 20 43 32 04 1a 41 88 03 4d 03 dd 44 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}