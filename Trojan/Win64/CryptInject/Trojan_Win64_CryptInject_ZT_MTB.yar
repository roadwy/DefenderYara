
rule Trojan_Win64_CryptInject_ZT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {48 89 c8 48 f7 e2 48 c1 ea 90 01 01 48 89 d0 48 c1 e0 90 01 01 48 01 d0 48 01 c0 48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 90 01 04 44 31 c8 41 88 00 48 83 85 90 01 05 48 8b 85 90 01 04 48 39 85 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}