
rule Trojan_BAT_NjRat_AANA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AANA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1c 13 0e 38 ?? fe ff ff 11 06 17 58 13 06 1f 09 13 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}