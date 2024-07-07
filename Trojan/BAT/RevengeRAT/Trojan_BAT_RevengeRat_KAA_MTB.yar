
rule Trojan_BAT_RevengeRat_KAA_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 16 11 04 8e 69 6f 90 01 02 00 0a 13 07 11 07 0a de 1c 00 11 06 2c 08 11 06 6f 90 01 01 00 00 0a 00 dc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}