
rule Trojan_Win64_CryptInject_TKZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 e1 31 4d df 29 4d a4 49 c7 c7 77 5b 00 00 29 55 ea 48 89 45 eb 0f b6 c6 4c 89 d2 4c 89 45 f6 33 45 db 4c 01 da 4c 03 4d ?? 8b 4d ab 89 d2 8b 7d c6 48 ff 04 24 49 c7 c4 03 00 00 00 4c 39 24 24 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}