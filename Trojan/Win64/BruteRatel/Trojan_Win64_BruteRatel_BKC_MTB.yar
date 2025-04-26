
rule Trojan_Win64_BruteRatel_BKC_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 da 0f b6 d2 8a 04 14 46 8d 14 18 45 0f b6 da 45 0f b6 d2 42 8a 34 14 40 88 34 14 42 88 04 14 02 04 14 0f b6 c0 8a 04 04 41 30 04 08 48 ff c1 eb c5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}