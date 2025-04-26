
rule Trojan_BAT_Zusy_NG_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 60 0a 00 09 17 58 0d 09 02 6f 19 00 00 0a fe 04 13 04 11 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}