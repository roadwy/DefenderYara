
rule Trojan_Win64_CryptInject_MG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b c2 48 8b 8c 24 80 00 00 00 48 8b 09 0f b6 04 01 88 44 24 20 48 8b 44 24 78 48 8b 00 48 8b 4c 24 28 0f b6 04 08 0f b6 4c 24 20 33 c1 89 44 24 24 0f b6 54 24 24 48 8d 4c 24 40 } //00 00 
	condition:
		any of ($a_*)
 
}