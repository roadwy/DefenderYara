
rule Trojan_BAT_QuasarRat_NA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {93 61 1f 61 5f 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}