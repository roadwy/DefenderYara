
rule Trojan_BAT_NjRat_NL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 8f 09 00 00 01 25 71 09 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 09 00 00 01 1f 62 28 de 00 00 06 39 1d f6 ff ff } //3
		$a_01_1 = {11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0f 38 f7 04 00 00 38 a2 02 00 00 1f 09 38 bf fe ff ff } //3
		$a_01_2 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 16 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}
rule Trojan_BAT_NjRat_NL_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 53 00 fe 0c 6d 00 fe 0c 6d 00 1f 17 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 77 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1d 64 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 55 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1e 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 53 00 58 fe 0e 6d 00 fe 0c 55 00 1b 62 fe 0c 77 00 58 fe 0c 55 00 61 fe 0c 6d 00 59 fe 0e 6d 00 fe 0c 6d 00 76 6c 6d 58 13 41 } //1
		$a_01_1 = {62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 1c 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1d 64 61 fe 0e 26 00 fe 0c 26 00 fe 0c 23 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1e 62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 13 00 58 fe 0e 26 00 fe 0c 23 00 1b 62 fe 0c 1c 00 58 fe 0c 23 00 61 fe 0c 26 00 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}