
rule Trojan_Win64_CryptInject_BVV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 2b d3 49 63 c8 48 8b c7 41 ff c0 48 f7 e1 48 c1 ea 04 48 8d 04 92 48 c1 e0 ?? 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01 49 ff c1 41 81 f8 00 ba 01 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}