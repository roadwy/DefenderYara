
rule Trojan_Win64_CryptInject_KKH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 ca 41 b8 ff ff ff ff 41 81 f0 ff 00 00 00 89 d1 44 31 c1 21 d1 48 63 c9 44 0f b6 04 08 48 8b 44 24 90 01 01 8b 4c 24 2c 0f b6 14 08 44 31 c2 88 14 08 8b 44 24 2c 83 c0 01 89 44 24 2c e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}