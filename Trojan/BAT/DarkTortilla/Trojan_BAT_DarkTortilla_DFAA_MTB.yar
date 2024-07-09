
rule Trojan_BAT_DarkTortilla_DFAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 3b 0b 00 70 17 8d ?? 00 00 01 25 16 02 a2 25 0c 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0d 28 ?? 00 00 0a 09 74 ?? 00 00 1b 16 91 2d 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}