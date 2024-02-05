
rule Trojan_Win64_CryptInject_KIM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b cb 4c 8d 15 90 01 04 b8 90 01 04 41 f7 e8 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 41 8b c8 2b c8 48 63 c1 42 0f b6 8c 10 90 01 04 43 32 8c 11 90 01 04 48 8b 85 90 01 04 41 88 0c 01 41 ff c0 4d 8d 49 90 01 01 44 3b 85 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}