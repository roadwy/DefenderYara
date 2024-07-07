
rule Trojan_BAT_DarkTortilla_HHAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.HHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 0d 11 08 28 90 01 02 00 0a 13 05 11 05 16 fe 02 13 09 11 09 2c 0d 11 04 09 16 11 05 6f 90 01 01 00 00 0a 00 00 00 00 11 05 16 fe 02 13 0a 11 0a 3a 90 01 01 ff ff ff 07 11 04 6f 90 01 01 00 00 0a 6f 90 01 02 00 0a 00 de 0e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}