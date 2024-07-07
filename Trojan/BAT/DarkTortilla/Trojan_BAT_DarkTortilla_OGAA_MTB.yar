
rule Trojan_BAT_DarkTortilla_OGAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.OGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 13 05 11 05 6f 90 01 01 01 00 0a 13 06 73 90 01 01 00 00 0a 0d 09 11 06 17 73 90 01 01 01 00 0a 13 04 11 04 02 16 02 8e 69 6f 90 01 01 01 00 0a 00 11 04 6f 90 01 01 01 00 0a 00 09 6f 90 01 01 00 00 0a 0c de 26 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}