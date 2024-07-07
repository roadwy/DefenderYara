
rule Trojan_BAT_DarkTortilla_GPAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 00 73 90 01 01 00 00 0a 13 05 00 11 05 11 04 17 73 90 01 01 00 00 0a 13 06 11 06 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 de 0e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}