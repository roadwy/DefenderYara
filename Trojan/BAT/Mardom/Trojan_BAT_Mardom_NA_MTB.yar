
rule Trojan_BAT_Mardom_NA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 5d 6f 19 00 00 0a 61 d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}