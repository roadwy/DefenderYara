
rule Trojan_BAT_NjRat_AANA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AANA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 90 01 01 00 00 01 1c 13 0e 38 90 01 01 fe ff ff 11 06 17 58 13 06 1f 09 13 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}