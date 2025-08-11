
rule Trojan_BAT_NjRat_PGN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.PGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 07 6c 23 00 00 00 00 00 00 00 40 5b 28 ?? 00 00 0a b7 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 11 07 18 d6 13 07 11 07 11 0b 13 0d 11 0d 31 ca } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}