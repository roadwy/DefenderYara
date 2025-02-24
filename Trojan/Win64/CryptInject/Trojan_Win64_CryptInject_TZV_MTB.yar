
rule Trojan_Win64_CryptInject_TZV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 08 0f b6 50 0a 0f b7 40 08 41 89 c0 41 c1 e8 08 34 66 41 80 f0 6c 80 f2 4a 48 89 4c 24 ?? 88 44 24 40 44 88 44 24 ?? 88 54 24 42 48 8d 54 24 ?? 41 b8 0b 00 00 00 4c 89 f9 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}