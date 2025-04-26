
rule Trojan_BAT_AveMaria_NEAH_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 2b e6 08 2b e5 6f 1f 00 00 0a 2b e0 08 2b df 6f 20 00 00 0a 2b da 07 2b d9 6f 21 00 00 0a 2b d4 08 2b d3 } //1
		$a_01_1 = {74 00 65 00 65 00 6e 00 66 00 61 00 73 00 68 00 69 00 6f 00 6e 00 62 00 64 00 } //1 teenfashionbd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}