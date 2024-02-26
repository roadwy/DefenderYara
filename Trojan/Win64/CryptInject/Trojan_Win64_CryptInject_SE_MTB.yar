
rule Trojan_Win64_CryptInject_SE_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 87 98 90 01 03 41 8b c8 41 ff c0 0f b6 14 01 49 ff c1 80 f2 90 01 01 41 88 51 90 01 01 44 3b 87 90 01 04 72 90 00 } //01 00 
		$a_01_1 = {53 70 49 6e 69 74 69 61 6c 69 7a 65 } //01 00  SpInitialize
		$a_01_2 = {4b 65 72 62 46 72 65 65 } //00 00  KerbFree
	condition:
		any of ($a_*)
 
}