
rule Trojan_BAT_Lazy_SPZM_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 58 09 5d 13 0f 08 11 0a 91 11 0e 61 08 11 0f 91 59 13 10 11 10 20 00 01 00 00 58 13 11 08 11 0a 11 11 20 ff 00 00 00 5f d2 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}