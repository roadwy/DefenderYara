
rule Trojan_BAT_NjRat_KAD_MTB{
	meta:
		description = "Trojan:BAT/NjRat.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 45 11 46 02 12 16 7b 90 01 02 00 04 6e 11 46 6a d6 b7 91 9c 11 46 17 d6 13 46 11 46 11 5d 31 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}