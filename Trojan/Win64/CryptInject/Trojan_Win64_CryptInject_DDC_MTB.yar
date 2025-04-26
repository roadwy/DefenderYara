
rule Trojan_Win64_CryptInject_DDC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8b c3 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 49 0f af cb 0f b6 44 0d ?? 43 32 44 04 ?? 41 88 40 ff 49 ff cf 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}