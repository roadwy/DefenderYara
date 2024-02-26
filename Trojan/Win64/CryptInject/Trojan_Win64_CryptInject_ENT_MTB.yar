
rule Trojan_Win64_CryptInject_ENT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ENT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 83 c1 04 33 41 fc 41 89 44 09 fc 44 8b 87 90 01 04 41 8d 80 fa 8b 62 d8 31 41 fc 48 ff ca 75 90 00 } //01 00 
		$a_03_1 = {0f b7 c1 66 c1 e8 08 41 32 41 01 88 42 01 41 8d 40 90 01 01 85 c0 74 0a c1 e9 10 41 32 49 02 88 4a 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}