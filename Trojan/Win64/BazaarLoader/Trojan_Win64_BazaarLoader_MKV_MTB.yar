
rule Trojan_Win64_BazaarLoader_MKV_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 03 d6 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 2b cb 8a 44 0c 20 42 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}