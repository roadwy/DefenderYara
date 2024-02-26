
rule Trojan_Win64_CryptInject_AC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 44 24 2c 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c 24 24 48 8b 54 24 48 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}