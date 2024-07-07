
rule Trojan_Win64_BazarLoader_MZB_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.MZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 60 b8 08 00 00 00 48 6b c0 90 02 01 48 8b 4c 24 28 48 8b 54 24 40 8b 04 02 8b 49 20 2b c8 8b c1 8b c0 48 8b 4c 24 28 48 03 c8 48 8b c1 48 89 44 24 48 c7 44 24 90 02 05 48 8b 44 24 28 8b 40 18 89 44 24 24 8b 44 24 24 d1 e8 89 44 24 20 8b 44 24 24 ff c0 89 44 24 34 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}