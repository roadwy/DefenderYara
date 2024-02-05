
rule Trojan_BAT_NjRat_NEAG_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 50 28 30 00 00 0a 0a 12 00 28 0a 00 00 06 } //0a 00 
		$a_01_1 = {0b 14 0c 16 0d 16 13 04 16 13 05 14 13 06 16 13 07 12 01 12 02 09 12 07 12 04 12 05 12 06 16 28 19 00 00 06 26 11 07 } //00 00 
	condition:
		any of ($a_*)
 
}