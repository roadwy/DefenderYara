
rule Trojan_BAT_NjRat_NEAP_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 09 11 09 16 11 04 a2 00 11 09 17 11 05 08 17 28 ?? 00 00 0a a2 00 11 09 18 11 06 08 17 28 ?? 00 00 0a a2 00 11 09 19 11 07 08 17 28 ?? 00 00 0a a2 00 11 09 1a 11 08 08 17 28 ?? 00 00 0a a2 00 11 09 28 ?? 00 00 0a 13 04 08 17 d6 0c 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}