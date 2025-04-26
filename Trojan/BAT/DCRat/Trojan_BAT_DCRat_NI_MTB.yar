
rule Trojan_BAT_DCRat_NI_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 1f 5f 62 02 7b ab 01 00 04 17 91 ?? ?? 00 00 00 5f 61 02 7b b2 01 00 04 5f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}