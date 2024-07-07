
rule Trojan_BAT_DarkTortilla_GSAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.GSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 11 04 75 90 01 01 00 00 1b 11 05 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 11 0c 11 0b 12 0c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}