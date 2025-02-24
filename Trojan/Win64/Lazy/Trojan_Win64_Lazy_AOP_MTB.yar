
rule Trojan_Win64_Lazy_AOP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 d1 30 c1 31 c0 28 c8 88 44 24 ?? 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 ?? 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 13 89 4c 24 ?? 88 44 24 2f 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}