
rule Trojan_Win64_CryptInject_AC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 44 24 2c 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c 24 24 48 8b 54 24 48 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CryptInject_AC_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f af ca 89 88 90 01 04 81 c1 90 01 04 8b 50 10 0f af d1 89 50 10 8b 48 34 81 e9 90 01 04 31 48 28 41 8b c8 41 0f af c8 41 ff c0 01 88 90 01 04 44 3b 40 5c 76 ae 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}