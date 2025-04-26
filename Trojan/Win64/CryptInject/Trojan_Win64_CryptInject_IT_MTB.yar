
rule Trojan_Win64_CryptInject_IT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.IT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 00 83 c0 ?? 89 44 24 ?? 48 8b 44 24 ?? 8b 4c 24 ?? 0f af 08 8b c1 8b 0c 24 33 c8 8b c1 89 04 24 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}