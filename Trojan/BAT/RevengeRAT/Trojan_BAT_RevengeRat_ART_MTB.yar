
rule Trojan_BAT_RevengeRat_ART_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 13 05 2b 28 07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f 2e 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_RevengeRat_ART_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 07 28 37 00 00 0a 3a 12 00 00 00 07 28 1d 00 00 06 28 38 00 00 0a 07 28 39 00 00 0a 26 07 28 37 00 00 0a 39 0e 00 00 00 07 18 28 3a 00 00 0a 07 28 39 00 00 0a 26 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}