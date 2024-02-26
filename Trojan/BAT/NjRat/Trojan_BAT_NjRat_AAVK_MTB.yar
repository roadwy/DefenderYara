
rule Trojan_BAT_NjRat_AAVK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 6a 13 07 16 0c 18 13 12 2b c2 d0 90 01 01 00 00 04 26 2b 51 1c 13 12 2b b5 d0 90 01 01 00 00 04 19 18 33 03 26 2b 01 26 01 11 0d 11 0c 11 09 17 28 90 01 01 00 00 06 11 06 11 07 6f 90 01 01 00 00 06 11 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}