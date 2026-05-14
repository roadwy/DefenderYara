
rule Trojan_BAT_DarkTortilla_WGA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.WGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1b 5d 16 fe 01 13 06 11 06 2c 0b 08 11 04 08 11 04 91 09 61 9c 00 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 07 11 07 2d d3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}