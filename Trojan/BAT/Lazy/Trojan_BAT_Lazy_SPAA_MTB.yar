
rule Trojan_BAT_Lazy_SPAA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 8f 90 01 03 01 25 71 90 01 03 01 06 11 07 91 61 d2 81 90 01 03 01 11 05 17 58 13 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}