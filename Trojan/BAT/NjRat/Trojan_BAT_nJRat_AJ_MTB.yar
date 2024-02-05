
rule Trojan_BAT_nJRat_AJ_MTB{
	meta:
		description = "Trojan:BAT/nJRat.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 00 02 16 28 45 00 00 0a 00 02 16 28 46 00 00 0a 00 28 0e 00 00 06 0a 06 28 47 00 00 0a 0b 02 07 72 1f 00 00 70 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}