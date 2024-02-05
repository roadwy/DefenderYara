
rule Trojan_Win64_CryptInject_GTB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 8b c1 48 8b 05 90 01 04 41 c1 e8 10 ff 80 a4 00 00 00 8b 82 50 01 00 00 33 05 34 5c 02 00 35 d2 a1 0c 00 89 05 29 5c 02 00 8b 4a 6c 2b 4a 48 8b 05 ed 5b 02 00 90 00 } //01 00 
		$a_03_1 = {03 c8 89 0d e3 5b 02 00 48 63 0d 30 5c 02 00 48 8b 82 90 01 04 44 88 04 01 45 8b c1 8b 05 1c 5c 02 00 ff c0 41 c1 e8 08 89 05 10 5c 02 00 48 63 c8 48 8b 82 90 01 04 44 88 04 01 ff 05 fc 5b 02 00 48 63 8a a4 00 00 00 48 8b 05 2a 5c 02 00 44 88 0c 01 ff 82 a4 00 00 00 48 81 fe c4 2f 00 00 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}