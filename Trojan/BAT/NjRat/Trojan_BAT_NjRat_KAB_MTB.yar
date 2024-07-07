
rule Trojan_BAT_NjRat_KAB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 04 11 07 11 05 59 91 1f 28 61 d2 61 d2 81 90 01 01 00 00 01 11 07 17 58 13 07 17 13 09 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}