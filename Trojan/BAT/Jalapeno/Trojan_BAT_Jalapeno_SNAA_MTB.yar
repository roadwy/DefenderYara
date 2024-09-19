
rule Trojan_BAT_Jalapeno_SNAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 6f ?? 00 00 0a 11 05 20 00 01 00 00 5d d2 59 20 ff 00 00 00 5f d2 13 06 11 06 0f 02 28 ?? 00 00 0a 20 00 01 00 00 5d d2 61 d2 13 06 11 04 11 05 11 06 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 11 04 6f ?? 00 00 0a fe 04 13 07 11 07 2d ab } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}