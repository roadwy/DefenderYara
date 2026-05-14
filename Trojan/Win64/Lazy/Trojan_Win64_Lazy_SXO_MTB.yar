
rule Trojan_Win64_Lazy_SXO_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 b9 61 00 00 00 f7 f9 8b c2 89 44 24 ?? eb ?? 6b 44 24 ?? 0a 03 44 24 ?? 99 b9 61 00 00 00 f7 f9 8b c2 89 44 } //30
		$a_03_1 = {b8 04 00 00 00 48 6b c0 00 8b 44 04 ?? 89 04 24 8b 04 24 c1 e8 08 83 e0 0f 89 44 24 ?? 8b 04 24 c1 e8 10 83 e0 0f } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}