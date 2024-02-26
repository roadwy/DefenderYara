
rule Trojan_Win64_CryptInject_MB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 c1 e9 08 48 69 c1 90 01 04 49 8b c8 48 2b c8 41 8a 04 18 32 04 11 41 88 04 18 49 ff c0 49 83 f8 71 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CryptInject_MB_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 87 a4 00 00 00 09 4f 10 8b 0d 90 01 04 81 f1 10 9d 01 00 0f af c1 89 87 a4 00 00 00 48 8b 05 90 01 04 48 63 48 5c 48 8b 87 90 01 04 44 88 04 01 48 8b 05 90 01 04 ff 40 5c 8b 05 90 01 04 05 76 12 f7 ff 31 05 90 01 04 49 81 f9 00 8e 01 00 0f 8c cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}