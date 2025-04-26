
rule Trojan_BAT_DarkTortilla_ATDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ATDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 17 da 0d 16 13 04 1f 0c 13 08 2b b6 11 04 17 5d 16 fe 01 13 05 11 05 2c 05 18 13 08 2b a4 1d 2b f9 02 11 04 02 11 04 91 20 d0 00 00 00 61 b4 9c 1d 13 08 2b 8d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}