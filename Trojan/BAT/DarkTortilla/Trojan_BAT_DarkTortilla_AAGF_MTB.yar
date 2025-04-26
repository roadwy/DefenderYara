
rule Trojan_BAT_DarkTortilla_AAGF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 0b 16 0c 2b 30 02 08 91 0d 08 18 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 ?? 00 00 06 9c 08 04 fe 01 13 06 11 06 2c 07 28 ?? 00 00 0a 0a 00 00 08 17 d6 0c 08 07 31 cc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}