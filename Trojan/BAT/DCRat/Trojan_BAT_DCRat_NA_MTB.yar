
rule Trojan_BAT_DCRat_NA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 00 17 61 5a 1e 63 d2 2a 02 ?? ?? 04 00 04 18 95 20 ff ff 00 00 5f d1 18 60 d1 13 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}