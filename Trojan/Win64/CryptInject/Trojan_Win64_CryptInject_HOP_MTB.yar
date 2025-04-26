
rule Trojan_Win64_CryptInject_HOP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.HOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 00 ea 45 0f b6 c2 42 8a 54 04 ?? 44 02 da 41 0f b6 cb 8a 44 0c 50 42 88 44 04 50 88 54 0c 50 42 02 54 04 ?? 0f b6 c2 8a 4c 04 50 41 30 09 4d 01 e9 4c 29 eb 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}