
rule Trojan_BAT_NjRat_ARAB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ARAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 02 06 91 11 05 61 11 04 08 91 61 b4 9c 08 03 6f ?? 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 06 17 d6 0a 06 11 06 31 d5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}