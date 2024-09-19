
rule Trojan_Win64_CryptInject_YI_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 39 e8 7d ?? 48 89 c2 48 8b 4c 24 ?? 83 e2 ?? 41 8a 54 15 ?? 41 32 14 04 88 14 01 48 ff c0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}