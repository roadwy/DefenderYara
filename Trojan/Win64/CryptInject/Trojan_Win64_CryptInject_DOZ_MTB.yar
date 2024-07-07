
rule Trojan_Win64_CryptInject_DOZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 09 33 c8 8b c1 48 8b 4c 24 90 01 01 88 01 8b 44 24 28 ff c0 89 44 24 28 8b 44 24 24 99 f7 7c 24 90 01 01 8b c2 85 c0 75 08 c7 44 24 28 00 00 00 00 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}