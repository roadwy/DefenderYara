
rule Trojan_Win64_CryptInject_NKK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.NKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 84 24 f0 00 00 00 8b 44 24 28 39 84 24 f0 00 00 00 73 90 01 01 48 63 8c 24 f0 00 00 00 48 8b 84 24 a0 00 00 00 44 0f b6 04 08 48 63 84 24 90 01 04 33 d2 b9 2c 00 00 00 48 f7 f1 0f b6 44 14 48 41 8b d0 33 d0 48 63 8c 24 90 01 04 48 8b 84 24 d8 00 00 00 88 14 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}