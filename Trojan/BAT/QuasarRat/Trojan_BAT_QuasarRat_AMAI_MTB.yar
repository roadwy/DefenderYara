
rule Trojan_BAT_QuasarRat_AMAI_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 06 09 91 11 ?? 61 20 00 01 00 00 5d d2 9c 06 09 06 09 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}