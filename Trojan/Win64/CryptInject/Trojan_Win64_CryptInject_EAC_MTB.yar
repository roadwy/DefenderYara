
rule Trojan_Win64_CryptInject_EAC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 c1 48 63 c8 48 8b 84 24 90 01 04 44 0f b6 04 08 48 63 84 24 90 01 04 33 d2 b9 3c 00 00 00 48 f7 f1 0f b6 44 14 70 41 8b d0 33 d0 8b 8c 24 88 01 00 00 8b 84 24 a8 01 00 00 90 00 } //05 00 
		$a_03_1 = {03 c1 2b 84 24 b4 00 00 00 03 84 24 40 01 00 00 2b 84 24 88 01 00 00 03 84 24 b4 00 00 00 8b 8c 24 40 01 00 00 0f af 8c 24 90 01 04 0f af 8c 24 90 01 04 03 c1 2b 84 24 90 01 04 03 84 24 90 01 04 48 63 c8 48 8b 84 24 90 01 04 88 14 08 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}