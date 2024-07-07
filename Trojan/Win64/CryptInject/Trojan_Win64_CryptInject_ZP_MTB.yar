
rule Trojan_Win64_CryptInject_ZP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 88 44 24 90 01 01 8b 4c 24 2c e8 90 01 04 89 44 24 90 01 01 0f b6 44 24 90 01 01 0f b6 4c 24 90 01 01 33 c1 0f b7 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}