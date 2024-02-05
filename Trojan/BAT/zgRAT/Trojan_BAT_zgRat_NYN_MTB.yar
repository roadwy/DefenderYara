
rule Trojan_BAT_zgRat_NYN_MTB{
	meta:
		description = "Trojan:BAT/zgRat.NYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 0c 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 73 90 01 01 00 00 06 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 73 90 01 01 00 00 06 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 18 2d 04 90 00 } //01 00 
		$a_01_1 = {5a 68 76 6d 68 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}