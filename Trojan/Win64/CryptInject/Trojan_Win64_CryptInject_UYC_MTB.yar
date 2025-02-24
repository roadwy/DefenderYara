
rule Trojan_Win64_CryptInject_UYC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.UYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 28 0f b6 04 08 05 45 07 00 00 35 50 38 00 00 88 44 24 20 48 8b 44 24 28 48 8b 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 41 b8 01 00 00 00 48 8d 54 24 20 48 8b c8 e8 83 fe ff ff c6 44 24 20 00 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}