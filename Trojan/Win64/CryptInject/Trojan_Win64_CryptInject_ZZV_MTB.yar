
rule Trojan_Win64_CryptInject_ZZV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 02 d4 45 0f b6 c2 42 8a 54 04 ?? 44 02 da 41 0f b6 cb 8a 44 0c ?? 42 88 44 04 ?? 88 54 0c 50 42 02 54 04 50 0f b6 c2 8a 4c 04 ?? 41 30 09 4d 03 cc 49 2b dc 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}