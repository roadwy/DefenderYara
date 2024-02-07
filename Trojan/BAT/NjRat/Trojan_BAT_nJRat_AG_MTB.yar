
rule Trojan_BAT_nJRat_AG_MTB{
	meta:
		description = "Trojan:BAT/nJRat.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 07 11 04 08 17 28 90 01 03 0a 11 05 08 17 28 90 01 03 0a 11 06 08 17 28 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}