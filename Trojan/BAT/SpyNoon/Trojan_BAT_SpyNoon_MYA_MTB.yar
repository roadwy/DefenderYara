
rule Trojan_BAT_SpyNoon_MYA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {22 70 d6 9c cc 0a 22 ab ab 8a cc 0b 22 80 a3 32 cc 0a 07 0a 28 90 01 03 06 28 90 01 03 2b 28 90 01 03 2b 72 7c 07 00 70 28 90 01 03 0a 72 d6 07 00 70 28 90 01 03 0a 28 90 01 03 06 0c 73 3c 00 00 06 0d 09 6f 90 01 03 06 00 73 50 00 00 06 13 04 11 04 08 6f 90 01 03 06 00 20 79 42 97 ff 13 05 20 35 ad cc fc 13 06 20 c9 55 8d ff 13 05 11 06 13 05 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}