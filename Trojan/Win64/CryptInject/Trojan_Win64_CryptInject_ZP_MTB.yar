
rule Trojan_Win64_CryptInject_ZP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 88 44 24 ?? 8b 4c 24 2c e8 ?? ?? ?? ?? 89 44 24 ?? 0f b6 44 24 ?? 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}