
rule Trojan_BAT_Khalesi_NA_MTB{
	meta:
		description = "Trojan:BAT/Khalesi.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 60 13 00 90 01 02 17 58 13 03 11 03 02 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}